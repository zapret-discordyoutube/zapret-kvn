"""Обновление ядра sing-box Extended из его релизов на GitHub.

Ядро приезжало только вместе со сборкой приложения, поэтому исправление в ядре
приходилось ждать до следующего релиза Zapret KVN. Модуль повторяет договор
обновления Xray: сначала показать доступную версию, менять файл только по
отдельному действию пользователя и никогда не оставлять каталог без рабочего
исполняемого файла.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import tempfile
from urllib.request import Request, urlopen
import zipfile

from PyQt6.QtCore import QThread, pyqtSignal

from ...constants import SINGBOX_PATH_DEFAULT
from ...profiles.path_utils import resolve_configured_path
from ...platform.windows.subprocess_utils import result_output_text, run_text


SINGBOX_RELEASES_API = "https://api.github.com/repos/shtorm-7/sing-box-extended/releases"

#: `sing-box-1.13.18-extended-2.6.5-windows-amd64-purego.zip`
ASSET_PATTERN = re.compile(r"^sing-box-.*-windows-amd64-purego\.zip$", re.IGNORECASE)

#: `v1.13.18-extended-2.6.5` — версия ядра и версия набора расширений.
VERSION_PATTERN = re.compile(
    r"v?(?P<core>\d+\.\d+\.\d+)-extended-(?P<extended>\d+\.\d+\.\d+)"
)

DOWNLOAD_LIMIT_BYTES = 200 * 1024 * 1024
METADATA_LIMIT_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class SingboxCoreRelease:
    version: str
    url: str
    notes: str = ""


@dataclass(slots=True)
class SingboxCoreUpdateResult:
    status: str
    message: str
    current_version: str = ""
    latest_version: str = ""
    updated: bool = False


def parse_version(text: str) -> tuple[int, ...] | None:
    """Разобрать версию расширенного ядра в сравнимый кортеж."""

    match = VERSION_PATTERN.search(str(text or ""))
    if not match:
        return None
    core = tuple(int(part) for part in match.group("core").split("."))
    extended = tuple(int(part) for part in match.group("extended").split("."))
    return core + extended


def is_newer(latest: str, current: str) -> bool:
    """Сравнить версии; неразобранная версия никогда не считается новее."""

    latest_parts = parse_version(latest)
    current_parts = parse_version(current)
    if latest_parts is None:
        return False
    if current_parts is None:
        return True
    return latest_parts > current_parts


def installed_version(exe: Path) -> str:
    """Спросить у ядра его версию."""

    try:
        result = run_text([str(exe), "version"], timeout=10.0)
    except Exception:
        return ""
    text = result_output_text(result)
    match = VERSION_PATTERN.search(text)
    return match.group(0) if match else ""


def _request_json(url: str) -> object:
    request = Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read(METADATA_LIMIT_BYTES).decode("utf-8"))


def _asset_of(release: dict) -> dict | None:
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and ASSET_PATTERN.match(str(asset.get("name") or "")):
            return asset
    return None


def resolve_release() -> SingboxCoreRelease | None:
    """Выбрать самый свежий стабильный релиз с нужным архивом."""

    payload = _request_json(SINGBOX_RELEASES_API)
    if not isinstance(payload, list):
        return None
    candidates: list[tuple[tuple[int, ...], dict, dict]] = []
    for item in payload:
        if not isinstance(item, dict) or item.get("draft") or item.get("prerelease"):
            continue
        asset = _asset_of(item)
        if asset is None:
            continue
        version = parse_version(str(item.get("tag_name") or ""))
        if version is None:
            continue
        candidates.append((version, item, asset))
    if not candidates:
        return None
    _, release, asset = max(candidates, key=lambda entry: entry[0])
    return SingboxCoreRelease(
        version=str(release.get("tag_name") or ""),
        url=str(asset.get("browser_download_url") or ""),
        notes=str(release.get("body") or ""),
    )


def _download(url: str, destination: Path, on_progress=None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(Request(url), timeout=60) as response:
        total = int(response.headers.get("Content-Length") or 0)
        downloaded = 0
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > DOWNLOAD_LIMIT_BYTES:
                    raise RuntimeError("Архив ядра больше допустимого размера")
                handle.write(chunk)
                if on_progress:
                    on_progress(downloaded, total)


def _install(archive: Path, target: Path) -> None:
    """Заменить исполняемый файл ядра, сохранив возможность отката."""

    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="singbox_core_extract_") as temp_dir:
        root = Path(temp_dir)
        with zipfile.ZipFile(archive, "r") as bundle:
            bundle.extractall(root)
        extracted = next((item for item in root.rglob("sing-box.exe")), None)
        if extracted is None:
            raise RuntimeError("sing-box.exe не найден в архиве")

        backup = root / "_backup.exe"
        if target.exists():
            shutil.copy2(target, backup)
        staged = target.with_name(target.name + ".new")
        shutil.copy2(extracted, staged)
        try:
            staged.replace(target)
        except OSError:
            # Ядро могло остаться запущенным: возвращаем прежний файл, чтобы
            # каталог не остался без работающего sing-box.exe.
            staged.unlink(missing_ok=True)
            if backup.exists() and not target.exists():
                shutil.copy2(backup, target)
            raise


def check_and_update_core(
    singbox_path: str,
    apply_update: bool = False,
    on_progress=None,
) -> SingboxCoreUpdateResult:
    exe = resolve_configured_path(
        singbox_path,
        default_path=SINGBOX_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    ) or SINGBOX_PATH_DEFAULT
    if not exe.exists():
        return SingboxCoreUpdateResult(
            status="error",
            message=f"sing-box.exe не найден: {exe}",
        )

    current = installed_version(exe)
    try:
        release = resolve_release()
    except Exception as exc:
        return SingboxCoreUpdateResult(
            status="error",
            message=f"Не удалось получить информацию о релизе: {exc}",
            current_version=current,
        )
    if release is None or not release.url:
        return SingboxCoreUpdateResult(
            status="error",
            message="Подходящий релиз sing-box Extended не найден",
            current_version=current,
        )

    if not is_newer(release.version, current):
        return SingboxCoreUpdateResult(
            status="ok",
            message=f"sing-box Extended актуален ({current or release.version})",
            current_version=current,
            latest_version=release.version,
        )

    if not apply_update:
        return SingboxCoreUpdateResult(
            status="update-available",
            message=f"Доступна версия {release.version}",
            current_version=current,
            latest_version=release.version,
        )

    with tempfile.TemporaryDirectory(prefix="singbox_core_download_") as temp_dir:
        archive = Path(temp_dir) / "core.zip"
        try:
            _download(release.url, archive, on_progress)
            _install(archive, exe)
        except Exception as exc:
            return SingboxCoreUpdateResult(
                status="error",
                message=f"Не удалось обновить ядро: {exc}",
                current_version=current,
                latest_version=release.version,
            )

    return SingboxCoreUpdateResult(
        status="ok",
        message=f"sing-box Extended обновлён до {release.version}",
        current_version=installed_version(exe) or release.version,
        latest_version=release.version,
        updated=True,
    )


class SingboxCoreUpdateWorker(QThread):
    finished_with_result = pyqtSignal(object)
    progress = pyqtSignal(int, int)

    def __init__(self, singbox_path: str, apply_update: bool, parent=None) -> None:
        super().__init__(parent)
        self._singbox_path = singbox_path
        self._apply_update = apply_update

    def run(self) -> None:
        result = check_and_update_core(
            self._singbox_path,
            apply_update=self._apply_update,
            on_progress=lambda done, total: self.progress.emit(int(done), int(total)),
        )
        self.finished_with_result.emit(result)
