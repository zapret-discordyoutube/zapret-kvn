"""Self-update: check Forgejo releases, download, verify and unpack.

Замену файлов выполняет ``updates.installer`` — новая сборка, запущенная
из распакованного архива.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

from ..network.http_utils import (
    HttpFetchError,
    HttpResponseTooLarge,
    build_opener,
    fetch_bytes,
)

from PyQt6.QtCore import QThread, pyqtSignal

from ..constants import APP_VERSION
from .installer.plan import APP_EXE_NAME, WORK_DIR_PREFIX

FORGEJO_RELEASE_API = (
    "https://git.zapret.moe/api/v1/repos/"
    "zapretkvn/zapret-kvn/releases/latest"
)
# Canonical owner first; legacy owners stay trusted because Forgejo redirects
# renamed repos, so older releases may still reference them.
FORGEJO_RELEASE_DOWNLOAD_PREFIXES = (
    "/zapretkvn/zapret-kvn/releases/download/",
    "/zapretdiscordyoutube/zapret-kvn/releases/download/",
)
FORGEJO_HOST = "git.zapret.moe"
USER_AGENT = f"ZapretKVN/{APP_VERSION}"
_UPDATE_CHECK_TIMEOUT = 8
_MAX_RELEASE_METADATA_BYTES = 1024 * 1024
_MAX_CHECKSUM_BYTES = 16 * 1024

_log = logging.getLogger(__name__)


def _resolve_extracted_app_dir(root: Path, exe_name: str) -> Path:
    if (root / exe_name).is_file():
        return root
    child_dirs = [path for path in root.iterdir() if path.is_dir()]
    if len(child_dirs) == 1 and (child_dirs[0] / exe_name).is_file():
        return child_dirs[0]
    for path in child_dirs:
        if (path / exe_name).is_file():
            return path
    return root


@dataclass(slots=True)
class AppUpdate:
    version: str
    tag: str
    download_url: str
    size: int
    notes: str
    digest_sha256: str = ""


@dataclass(slots=True)
class PreparedUpdate:
    """Скачанное, проверенное и распакованное обновление, готовое к установке."""

    version: str
    # Распакованная сборка: каталог с ZapretKVN.exe новой версии.
    source_dir: Path
    # Временный каталог загрузки целиком.
    work_dir: Path


class UpdateRejected(Exception):
    """Архив непригоден, и повторная загрузка этого не исправит."""


_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")


def _parse_semver(version: str) -> tuple[int, int, int, list[str]] | None:
    match = _SEMVER_RE.search(version.strip().lstrip("v"))
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    prerelease = suffix.split(".") if suffix else []
    return int(major), int(minor), int(patch), prerelease


def _compare_prerelease(left: list[str], right: list[str]) -> int:
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1

    for left_part, right_part in zip(left, right):
        if left_part == right_part:
            continue
        left_is_num = left_part.isdigit()
        right_is_num = right_part.isdigit()
        if left_is_num and right_is_num:
            left_num = int(left_part)
            right_num = int(right_part)
            if left_num != right_num:
                return 1 if left_num > right_num else -1
            continue
        if left_is_num != right_is_num:
            return -1 if left_is_num else 1
        return 1 if left_part > right_part else -1

    if len(left) == len(right):
        return 0
    return 1 if len(left) > len(right) else -1


def _is_newer_version(latest: str, current: str) -> bool:
    latest_parts = _parse_semver(latest)
    current_parts = _parse_semver(current)
    if latest_parts is None or current_parts is None:
        return latest.strip().lstrip("v") != current.strip().lstrip("v")

    latest_core = latest_parts[:3]
    current_core = current_parts[:3]
    if latest_core != current_core:
        return latest_core > current_core
    return _compare_prerelease(latest_parts[3], current_parts[3]) > 0


def _extract_digest(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    match = re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", text)
    return match.group(0) if match else ""


def _sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_trusted_release_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and (parsed.hostname or "").lower() == FORGEJO_HOST
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
        and parsed.path.startswith(FORGEJO_RELEASE_DOWNLOAD_PREFIXES)
    )


def _is_trusted_release_api_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
        expected = urlsplit(FORGEJO_RELEASE_API)
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and (parsed.hostname or "").lower() == FORGEJO_HOST
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
        and parsed.path.rstrip("/") == expected.path.rstrip("/")
    )


class _ReleaseClient:
    """Small, retrying transport for release metadata and checksums."""

    def __init__(self, proxy_url: str | None = None):
        self._proxy_url = proxy_url

    def _fetch(self, request: Request, *, max_bytes: int):
        return fetch_bytes(
            request,
            timeout=_UPDATE_CHECK_TIMEOUT,
            max_bytes=max_bytes,
            proxy_url=self._proxy_url,
            attempts_per_route=2,
            # A connected app already has an explicit, verified local route;
            # use it first so a broken public DNS/backend does not stall UI.
            prefer_proxy=bool(self._proxy_url),
            # Forgejo can return a route/region-specific legal-policy response.
            # Do not retry it on the same route; fail over to the other egress.
            fallback_http_statuses=frozenset({451}),
        )

    def fetch_release(self) -> dict:
        request = Request(
            FORGEJO_RELEASE_API,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        response = self._fetch(request, max_bytes=_MAX_RELEASE_METADATA_BYTES)
        if not _is_trusted_release_api_url(response.final_url):
            raise ValueError("Сервер обновлений перенаправил запрос на недоверенный адрес")
        payload = json.loads(response.data.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Сервер обновлений вернул некорректный ответ")
        return payload

    def fetch_checksum(self, url: str) -> str:
        if not _is_trusted_release_url(url):
            raise ValueError("Forgejo вернул недоверенную ссылку на контрольную сумму")
        request = Request(url, headers={"User-Agent": USER_AGENT})
        response = self._fetch(request, max_bytes=_MAX_CHECKSUM_BYTES)
        if not _is_trusted_release_url(response.final_url):
            raise ValueError("Forgejo перенаправил контрольную сумму на недоверенный адрес")
        return response.data.decode("utf-8", errors="replace")


def _find_available_update(proxy_url: str | None = None) -> AppUpdate | None:
    client = _ReleaseClient(proxy_url)
    data = client.fetch_release()
    tag = str(data.get("tag_name") or "")

    if not _is_newer_version(tag, APP_VERSION):
        return None

    asset = None
    for candidate in data.get("assets", []):
        name = str(candidate.get("name") or "").lower()
        if name.endswith(".zip") and "windows" in name and "x64" in name:
            asset = candidate
            break

    if not asset:
        raise ValueError(f"Релиз {tag} найден, но отсутствует Windows zip-архив")

    asset_url = str(asset.get("browser_download_url") or "")
    if not _is_trusted_release_url(asset_url):
        raise ValueError(f"Релиз {tag} содержит недоверенную ссылку на архив")

    digest = _extract_digest(str(asset.get("digest") or ""))
    if not digest:
        asset_name = str(asset.get("name") or "")
        sidecar = None
        for suffix in (".sha256", ".dgst"):
            expected = f"{asset_name}{suffix}".lower()
            sidecar = next(
                (
                    candidate for candidate in data.get("assets", [])
                    if str(candidate.get("name") or "").lower() == expected
                ),
                None,
            )
            if sidecar:
                break
        if sidecar:
            sidecar_url = str(sidecar.get("browser_download_url") or "")
            digest = _extract_digest(client.fetch_checksum(sidecar_url))
    if not digest:
        raise ValueError(f"Релиз {tag} найден, но архив не содержит SHA-256")

    return AppUpdate(
        version=tag.lstrip("v"),
        tag=tag,
        download_url=asset_url,
        size=int(asset.get("size") or 0),
        notes=str(data.get("body") or ""),
        digest_sha256=digest,
    )


def _describe_update_check_error(error: BaseException, *, has_proxy: bool) -> str:
    if isinstance(error, HttpFetchError):
        if any(
            isinstance(cause, urllib.error.HTTPError) and cause.code == 451
            for cause in error.causes
        ):
            if has_proxy:
                return (
                    "Сервер обновлений недоступен в текущем регионе. "
                    "Переключитесь на другой сервер и повторите попытку."
                )
            return (
                "Сервер обновлений недоступен напрямую в текущем регионе. "
                "Подключитесь к серверу и повторите попытку."
            )
        if has_proxy:
            return (
                "Не удалось связаться с сервером обновлений напрямую и через прокси. "
                "Проверьте подключение или переключитесь на рабочий сервер."
            )
        return (
            "Сервер обновлений временно не отвечает. "
            "Проверьте подключение и повторите попытку."
        )
    if isinstance(error, HttpResponseTooLarge):
        return "Сервер обновлений вернул слишком большой ответ"
    if isinstance(error, json.JSONDecodeError):
        return "Сервер обновлений вернул некорректный ответ"
    if isinstance(error, urllib.error.HTTPError):
        return f"Сервер обновлений ответил с ошибкой HTTP {error.code}"
    if isinstance(error, (urllib.error.URLError, TimeoutError, ConnectionError, OSError)):
        return (
            "Не удалось установить защищённое соединение с сервером обновлений. "
            "Проверьте подключение и повторите попытку."
        )
    return str(error) or "Не удалось проверить обновления"


class UpdateChecker(QThread):
    """Check the project Forgejo for a newer release."""

    result = pyqtSignal(object)  # AppUpdate | None
    error = pyqtSignal(str)

    def __init__(self, proxy_url: str | None = None, parent=None):
        super().__init__(parent)
        self._proxy_url = proxy_url

    def run(self) -> None:
        try:
            self.result.emit(_find_available_update(self._proxy_url))
        except Exception as exc:
            _log.warning("Update check failed: %s", exc, exc_info=True)
            self.error.emit(
                _describe_update_check_error(exc, has_proxy=bool(self._proxy_url))
            )
            return


_DOWNLOAD_TIMEOUT = 30  # seconds — per socket operation (connect + each read)
_NUM_SEGMENTS = 4       # parallel download segments
_CHUNK_SIZE = 1024 * 1024  # 1 MB


def _purge_stale_update_dirs(prefix: str = WORK_DIR_PREFIX, keep: int = 0) -> int:
    """Удалить каталоги прошлых загрузок.

    Каждый хранит архив и распакованную сборку — сотни мегабайт; прерванные
    попытки без уборки накапливали у пользователей гигабайты.
    """

    root = Path(tempfile.gettempdir())
    removed = 0
    try:
        candidates = sorted(
            (item for item in root.glob(f"{prefix}*") if item.is_dir()),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return 0
    for stale in candidates[keep:]:
        before = stale.exists()
        shutil.rmtree(stale, ignore_errors=True)
        if before and not stale.exists():
            removed += 1
    return removed


class UpdateDownloader(QThread):
    """Download, verify and unpack the update."""

    progress = pyqtSignal(int)       # percent 0-100
    status = pyqtSignal(str)         # human-readable status message
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(
        self,
        update: AppUpdate,
        proxy_url: str | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._update = update
        self._proxy_url = proxy_url
        self.prepared: PreparedUpdate | None = None
        # Сбой, который повторится при любой следующей загрузке этого же
        # архива (контрольная сумма, содержимое). Сетевые ошибки — нет.
        self.failure_permanent = False

    @property
    def update(self) -> AppUpdate:
        return self._update

    # ── download helpers ────────────────────────────────────────

    def _build_opener(self, proxy_url: str | None) -> urllib.request.OpenerDirector:
        if proxy_url:
            handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            return build_opener(handler)
        return build_opener(urllib.request.ProxyHandler({}))

    def _supports_range(self, url: str, opener: urllib.request.OpenerDirector) -> tuple[bool, int]:
        """HEAD request to check Range support and get Content-Length."""
        req = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            accepts = resp.headers.get("Accept-Ranges", "").lower()
            length = int(resp.headers.get("Content-Length", 0))
            return accepts == "bytes" and length > 0, length

    def _download_segment(
        self,
        url: str,
        proxy_url: str | None,
        start: int,
        end: int,
        seg_path: Path,
        seg_index: int,
        lock: threading.Lock,
        progress_arr: list[int],
        total: int,
    ) -> None:
        """Download one segment with Range header."""
        opener = self._build_opener(proxy_url)
        expected_length = end - start + 1
        req = Request(url, headers={
            "User-Agent": USER_AGENT,
            "Range": f"bytes={start}-{end}",
        })
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            status_code = getattr(resp, "status", None)
            content_range = resp.headers.get("Content-Range", "")
            if status_code != 206 or not content_range.startswith(f"bytes {start}-{end}/"):
                raise RuntimeError("Сервер некорректно ответил на Range-запрос")

            downloaded = 0
            with open(seg_path, "wb") as f:
                while True:
                    chunk = resp.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    with lock:
                        progress_arr[seg_index] += len(chunk)
                        done = sum(progress_arr)
                        self.progress.emit(int(done * 100 / total))
            if downloaded != expected_length:
                raise RuntimeError("Сервер вернул неполный фрагмент архива")

    def _download_single(self, url: str, opener: urllib.request.OpenerDirector, zip_path: Path) -> None:
        """Single-connection fallback download."""
        req = Request(url, headers={"User-Agent": USER_AGENT})
        with opener.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(_CHUNK_SIZE)
                    if not chunk:
                        if downloaded == 0:
                            raise TimeoutError("Сервер не отдаёт данные")
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        self.progress.emit(int(downloaded * 100 / total))

    def _download(self, zip_path: Path, proxy_url: str | None) -> None:
        """Download update zip with multi-segment acceleration.

        Tries parallel Range-based download first; falls back to single
        connection if the server doesn't support Range requests.
        """
        url = self._update.download_url
        opener = self._build_opener(proxy_url)

        # Check if server supports Range requests
        try:
            supports_range, total = self._supports_range(url, opener)
        except Exception:
            supports_range, total = False, 0

        if not supports_range or total == 0 or total < _NUM_SEGMENTS * _CHUNK_SIZE:
            _log.info("Server does not support Range or file too small — single download")
            self._download_single(url, opener, zip_path)
            return

        # Split into segments
        seg_size = total // _NUM_SEGMENTS
        segments: list[tuple[int, int]] = []
        for i in range(_NUM_SEGMENTS):
            start = i * seg_size
            end = total - 1 if i == _NUM_SEGMENTS - 1 else (i + 1) * seg_size - 1
            segments.append((start, end))

        # Prepare temp segment files
        seg_dir = zip_path.parent / "_segments"
        seg_dir.mkdir(exist_ok=True)
        seg_paths = [seg_dir / f"seg_{i}" for i in range(_NUM_SEGMENTS)]

        lock = threading.Lock()
        progress_arr = [0] * _NUM_SEGMENTS

        # Download segments in parallel
        try:
            with ThreadPoolExecutor(max_workers=_NUM_SEGMENTS) as pool:
                futures = []
                for i, (start, end) in enumerate(segments):
                    fut = pool.submit(
                        self._download_segment,
                        url, proxy_url, start, end,
                        seg_paths[i], i, lock, progress_arr, total,
                    )
                    futures.append(fut)

                # Re-raise any segment exception
                for fut in futures:
                    fut.result()

            # Concatenate segments into final file
            with open(zip_path, "wb") as out:
                for sp in seg_paths:
                    with open(sp, "rb") as seg_f:
                        shutil.copyfileobj(seg_f, out)
        except Exception as exc:
            _log.warning("Segmented download failed, falling back to single download: %s", exc)
            if zip_path.exists():
                zip_path.unlink()
            self.progress.emit(0)
            self._download_single(url, opener, zip_path)
        finally:
            # Clean up segment temp files
            shutil.rmtree(seg_dir, ignore_errors=True)

    # ── thread entry ────────────────────────────────────────────

    def run(self) -> None:
        work_dir: Path | None = None
        try:
            _purge_stale_update_dirs()
            work_dir = Path(tempfile.mkdtemp(prefix=WORK_DIR_PREFIX))
            archive = work_dir / "update.zip"
            self._fetch(archive)
            self._verify(archive)
            source_dir = self._unpack(archive, work_dir / "extracted")
            # Дальше архив не нужен, а места занимает столько же, сколько сборка.
            archive.unlink(missing_ok=True)
            self.prepared = PreparedUpdate(self._update.version, source_dir, work_dir)
        except Exception as exc:
            self.failure_permanent = isinstance(exc, (UpdateRejected, zipfile.BadZipFile))
            if work_dir is not None:
                shutil.rmtree(work_dir, ignore_errors=True)
            self.error.emit(str(exc) or "Не удалось подготовить обновление")
            return
        self.finished_ok.emit()

    def _fetch(self, archive: Path) -> None:
        """Скачать архив напрямую, а при неудаче — через активный прокси."""

        routes: list[tuple[str, str | None]] = [("Загрузка напрямую...", None)]
        if self._proxy_url:
            routes.append(("Загрузка через прокси...", self._proxy_url))
        for status, proxy_url in routes:
            self.status.emit(status)
            self.progress.emit(0)
            try:
                self._download(archive, proxy_url)
                return
            except Exception as exc:
                _log.warning("Update download failed (%s): %s", status, exc)
                archive.unlink(missing_ok=True)
        if self._proxy_url:
            raise RuntimeError(
                "Не удалось скачать обновление ни напрямую, ни через прокси.\n"
                "Переключитесь на рабочий сервер и попробуйте снова."
            )
        raise RuntimeError(
            "Не удалось скачать обновление.\n"
            "Переключитесь на рабочий сервер и попробуйте снова."
        )

    def _verify(self, archive: Path) -> None:
        self.status.emit("Проверка архива...")
        expected = _extract_digest(self._update.digest_sha256)
        if not expected:
            raise UpdateRejected("У релизного архива отсутствует SHA-256")
        if _sha256_file(archive).lower() != expected:
            raise UpdateRejected("Контрольная сумма архива не совпадает")
        self.progress.emit(100)

    def _unpack(self, archive: Path, destination: Path) -> Path:
        self.status.emit("Распаковка...")
        with zipfile.ZipFile(archive, "r") as bundle:
            bundle.extractall(destination)
        source_dir = _resolve_extracted_app_dir(destination, APP_EXE_NAME)
        if not (source_dir / APP_EXE_NAME).is_file():
            raise UpdateRejected(f"Архив обновления не содержит {APP_EXE_NAME}")
        return source_dir
