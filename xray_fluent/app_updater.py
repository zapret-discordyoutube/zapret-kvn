"""Self-update: check Forgejo releases, download, verify, extract, restart."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile  # kept for legacy .zip support
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

from .http_utils import (
    HttpFetchError,
    HttpResponseTooLarge,
    build_opener,
    fetch_bytes,
)

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import APP_VERSION, BASE_DIR

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


def _powershell_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _write_utf8_bom_text(path: Path, text: str) -> None:
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))


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


def _build_update_script(
    *,
    current_pid: int,
    source_dir: Path,
    app_dir: Path,
    exe_name: str,
    tmp_dir: Path,
    restart_in_tray: bool,
) -> str:
    """Собрать PowerShell-скрипт, который заменяет файлы после выхода приложения."""

    return "\r\n".join([
        "$ErrorActionPreference = 'Stop'",
        f"$pidToWait = {current_pid}",
        f"$sourceDir = {_powershell_literal(str(source_dir))}",
        f"$appDir = {_powershell_literal(str(app_dir))}",
        f"$exePath = {_powershell_literal(str(app_dir / exe_name))}",
        f"$tempDir = {_powershell_literal(str(tmp_dir))}",
        "$logDir = Join-Path (Join-Path $appDir 'data') 'logs'",
        "$runtimeDir = Join-Path (Join-Path $appDir 'data') 'runtime'",
        "$errorLog = Join-Path $logDir 'update_error.log'",
        "$preserveNames = @('data')",
        "$backupDir = Join-Path $runtimeDir 'update_backup'",
        "$backupReplaceDir = Join-Path $backupDir 'replace'",
        "$backupStaleDir = Join-Path $backupDir 'stale'",
        "Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue",
        "New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null",
        "New-Item -ItemType Directory -Path $backupReplaceDir -Force | Out-Null",
        "New-Item -ItemType Directory -Path $backupStaleDir -Force | Out-Null",
        # Ядра живут отдельными процессами внутри каталога приложения и
        # держат core\ открытым, поэтому ожидания одного лишь основного
        # процесса не хватало: перемещение падало на занятом каталоге.
        "function Stop-AppProcesses {",
        "    param([string] $root, [int] $timeoutMs)",
        "    $deadline = (Get-Date).AddMilliseconds($timeoutMs)",
        "    while ((Get-Date) -lt $deadline) {",
        "        $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {",
        "            if ($_.Id -eq $PID) { return $false }",
        "            try { $path = $_.Path } catch { return $false }",
        "            $path -and $path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)",
        "        })",
        "        if ($running.Count -eq 0) { return }",
        "        foreach ($item in $running) {",
        "            Stop-Process -Id $item.Id -Force -ErrorAction SilentlyContinue",
        "        }",
        "        Start-Sleep -Milliseconds 300",
        "    }",
        "}",
        # Даже после завершения процесса Windows освобождает файл не мгновенно.
        "function Move-WithRetry {",
        "    param([string] $path, [string] $destination, [int] $attempts = 20)",
        # -ErrorAction Stop обязателен: без него Move-Item сообщает об
        # ошибке не-терминирующим способом, catch не срабатывает, и функция
        # отчитывается об успехе, оставив файл на месте.
        "    for ($try = 1; $try -lt $attempts; $try++) {",
        "        try {",
        "            Move-Item -LiteralPath $path -Destination $destination -Force -ErrorAction Stop",
        "            return",
        "        } catch {",
        "            Start-Sleep -Milliseconds 500",
        "        }",
        "    }",
        "    Move-Item -LiteralPath $path -Destination $destination -Force -ErrorAction Stop",
        "}",
        "for ($i = 0; $i -lt 120; $i++) {",
        "    if (-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)) { break }",
        "    Start-Sleep -Milliseconds 500",
        "}",
        "$proc = Get-Process -Id $pidToWait -ErrorAction SilentlyContinue",
        "if ($proc) { Stop-Process -Id $pidToWait -Force }",
        "$appRoot = [System.IO.Path]::GetFullPath($appDir).TrimEnd('\\') + '\\'",
        "Stop-AppProcesses -root $appRoot -timeoutMs 30000",
        "$sourceItems = @(Get-ChildItem -LiteralPath $sourceDir -Force | Where-Object { $preserveNames -notcontains $_.Name })",
        "$sourceNames = @($sourceItems | ForEach-Object { $_.Name })",
        "try {",
        "    Get-ChildItem -LiteralPath $appDir -Force | Where-Object { $preserveNames -notcontains $_.Name } | ForEach-Object {",
        "        $backupTarget = if ($sourceNames -contains $_.Name) { $backupReplaceDir } else { $backupStaleDir }",
        "        Move-WithRetry -path $_.FullName -destination $backupTarget",
        "    }",
        "    foreach ($item in $sourceItems) {",
        "        Copy-Item -LiteralPath $item.FullName -Destination $appDir -Recurse -Force",
        "    }",
        (
            "    $started = Start-Process -FilePath $exePath -ArgumentList '--tray' -WorkingDirectory $appDir -PassThru -ErrorAction Stop"
            if restart_in_tray
            else "    $started = Start-Process -FilePath $exePath -WorkingDirectory $appDir -PassThru -ErrorAction Stop"
        ),
        "    Start-Sleep -Seconds 5",
        "    if ($started.HasExited) {",
        "        throw ('Updated application exited immediately with code ' + $started.ExitCode)",
        "    }",
        "    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue",
        "}",
        "catch {",
        "    Get-ChildItem -LiteralPath $appDir -Force -ErrorAction SilentlyContinue | Where-Object { $preserveNames -notcontains $_.Name } | ForEach-Object {",
        "        Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue",
        "    }",
        "    Get-ChildItem -LiteralPath $backupReplaceDir -Force -ErrorAction SilentlyContinue | ForEach-Object {",
        "        Move-WithRetry -path $_.FullName -destination $appDir",
        "    }",
        "    Get-ChildItem -LiteralPath $backupStaleDir -Force -ErrorAction SilentlyContinue | ForEach-Object {",
        "        Move-WithRetry -path $_.FullName -destination $appDir",
        "    }",
        (
            "    if (Test-Path -LiteralPath $exePath) { Start-Process -FilePath $exePath -ArgumentList '--tray' -WorkingDirectory $appDir -ErrorAction SilentlyContinue | Out-Null }"
            if restart_in_tray
            else "    if (Test-Path -LiteralPath $exePath) { Start-Process -FilePath $exePath -WorkingDirectory $appDir -ErrorAction SilentlyContinue | Out-Null }"
        ),
        "    New-Item -ItemType Directory -Path $logDir -Force | Out-Null",
        "    ($_ | Out-String) | Set-Content -LiteralPath $errorLog -Encoding UTF8",
        "    Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue",
        "    throw",
        "}",
        "Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue",
        "",
    ])


class UpdateDownloader(QThread):
    """Download and extract update, then launch restart script."""

    progress = pyqtSignal(int)       # percent 0-100
    status = pyqtSignal(str)         # human-readable status message
    finished_ok = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(
        self,
        update: AppUpdate,
        proxy_url: str | None = None,
        restart_in_tray: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._update = update
        self._proxy_url = proxy_url
        self._restart_in_tray = restart_in_tray

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

    # ── main thread entry ───────────────────────────────────────

    def run(self) -> None:
        tmp_dir: Path | None = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="zapretkvn_update_"))
            zip_path = tmp_dir / "update.zip"

            downloaded_ok = False

            # Attempt 1: direct (no proxy)
            self.status.emit("Загрузка напрямую...")
            try:
                self._download(zip_path, None)
                downloaded_ok = True
            except Exception as exc:
                _log.warning("Direct download failed: %s", exc)
                if self._proxy_url:
                    self.status.emit(
                        "Прямая загрузка не удалась, пробую через прокси..."
                    )
                    self.progress.emit(0)
                    # clean partial file
                    if zip_path.exists():
                        zip_path.unlink()

            # Attempt 2: through proxy (if available)
            if not downloaded_ok and self._proxy_url:
                self.status.emit("Загрузка через прокси...")
                try:
                    self._download(zip_path, self._proxy_url)
                    downloaded_ok = True
                except Exception as exc:
                    _log.warning("Proxy download failed: %s", exc)

            if not downloaded_ok:
                msg = (
                    "Не удалось скачать обновление.\n"
                    "Переключитесь на рабочий сервер и попробуйте снова."
                )
                if self._proxy_url:
                    msg = (
                        "Не удалось скачать обновление ни напрямую, ни через прокси.\n"
                        "Переключитесь на рабочий сервер и попробуйте снова."
                    )
                self.error.emit(msg)
                # cleanup
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            self.status.emit("Проверка архива...")
            expected_hash = _extract_digest(self._update.digest_sha256)
            if not expected_hash:
                self.error.emit("У релизного архива отсутствует SHA-256")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            real_hash = _sha256_file(zip_path)
            if real_hash.lower() != expected_hash.lower():
                self.error.emit("Контрольная сумма архива не совпадает")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            self.progress.emit(100)
            self.status.emit("Распаковка...")

            # Extract
            extract_dir = tmp_dir / "extracted"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            exe_name = "ZapretKVN.exe"
            source_dir = _resolve_extracted_app_dir(extract_dir, exe_name)
            if not (source_dir / exe_name).is_file():
                self.error.emit("Архив обновления не содержит ZapretKVN.exe")
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return

            # Write restart script
            current_pid = os.getpid()
            app_dir = BASE_DIR
            script = tmp_dir / "_update.ps1"
            script_text = _build_update_script(
                current_pid=current_pid,
                source_dir=source_dir,
                app_dir=app_dir,
                exe_name=exe_name,
                tmp_dir=tmp_dir,
                restart_in_tray=self._restart_in_tray,
            )
            _write_utf8_bom_text(script, script_text)

            # Launch script and exit
            subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-WindowStyle",
                    "Hidden",
                    "-File",
                    str(script),
                ],
                creationflags=0x08000000,
                close_fds=True,
            )

            self.finished_ok.emit()

        except Exception as exc:
            if tmp_dir is not None:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            self.error.emit(str(exc))
