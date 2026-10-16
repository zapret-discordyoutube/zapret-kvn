"""Прямые HTTPS-запросы приложения — неотличимые от Chrome на проводе.

Собственный TLS Python (``ssl``) отличается от любого браузера с первого
пакета: набор шифров, порядок расширений, нет GREASE. Поэтому прямые запросы
приложения (DoH для адреса сервера) идут через сетевой стек самого Chromium
(Cronet), встроенный в наше ядро: ``sing-box tools browser-fetch --serve``
(патч ``core-patches/browser-fetch.patch``). ClientHello, HTTP/2 SETTINGS,
порядок псевдозаголовков и User-Agent — как у Chrome той же версии.

Один долгоживущий процесс с прогретым движком: запросы и ответы — по одной
JSON-строке, ``id`` связывает ответ с запросом. Процесс поднимается при первом
запросе и перезапускается, если упал.
"""

from __future__ import annotations

import base64
from concurrent.futures import Future
from dataclasses import dataclass, field
import itertools
import json
import os
from pathlib import Path
import subprocess
import threading
from typing import Callable, Iterable

from ..constants import SINGBOX_PATH_DEFAULT

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class BrowserFetchError(OSError):
    """Запрос не выполнен (сеть, TLS, таймаут) — ответа сервера нет."""


class BrowserFetchUnavailable(BrowserFetchError):
    """Браузерного стека нет (ядро не найдено или не запускается)."""


@dataclass(frozen=True)
class BrowserResponse:
    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""
    truncated: bool = False
    redirect_refused: str = ""

    def header(self, name: str) -> str:
        wanted = name.lower()
        return next((value for key, value in self.headers if key.lower() == wanted), "")


@dataclass
class _Process:
    proc: subprocess.Popen
    pending: dict[int, Future] = field(default_factory=dict)


class BrowserFetchService:
    """Клиент процесса ``browser-fetch --serve``; потокобезопасен."""

    def __init__(
        self,
        executable: Callable[[], Path] = lambda: Path(SINGBOX_PATH_DEFAULT),
        launcher: Callable[[Path], list[str]] | None = None,
        *,
        enabled: bool = False,
    ) -> None:
        # Своё ядро из поставки, а не путь из настроек: патч browser-fetch есть
        # только в нём.
        self._executable = executable
        self._launcher = launcher or (lambda exe: [str(exe), "tools", "browser-fetch", "--serve"])
        self._lock = threading.Lock()
        self._process: _Process | None = None
        self._ids = itertools.count(1)
        self._closed = False
        # Выключена, пока приложение не включит её при старте (main.py): тесты
        # и утилиты не запускают ядро и не ходят в сеть сами.
        self._enabled = enabled

    def enable(self) -> None:
        self._enabled = True

    def available(self) -> bool:
        if not self._enabled:
            return False
        try:
            return self._executable().is_file()
        except OSError:
            return False

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Iterable[tuple[str, str]] = (),
        body: bytes = b"",
        timeout: float = 10.0,
        max_bytes: int = 0,
    ) -> BrowserResponse:
        request = {"url": url, "method": method, "headers": [[k, v] for k, v in headers],
                   "timeout_ms": max(1, int(timeout * 1000))}
        if body:
            request["body"] = base64.b64encode(body).decode("ascii")
        if max_bytes:
            request["max_bytes"] = int(max_bytes)
        future = self._submit(request)
        try:
            # Таймаут запроса держит само ядро; здесь — запас на запуск процесса.
            reply = future.result(timeout=timeout + 5.0)
        except TimeoutError as exc:
            raise BrowserFetchError(f"browser-fetch: нет ответа за {timeout:.0f} с") from exc
        if reply.get("unavailable"):
            raise BrowserFetchUnavailable(f"browser-fetch: {reply.get('error')}")
        if reply.get("error"):
            raise BrowserFetchError(f"browser-fetch: {reply['error']}")
        return BrowserResponse(
            status=int(reply.get("status") or 0),
            headers=tuple((str(k), str(v)) for k, v in reply.get("headers") or ()),
            body=base64.b64decode(reply.get("body") or ""),
            truncated=bool(reply.get("truncated")),
            redirect_refused=str(reply.get("redirect_refused") or ""),
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True
            process, self._process = self._process, None
        if process is not None:
            self._stop(process)

    # ── внутреннее ──

    def _submit(self, request: dict) -> Future:
        future: Future = Future()
        with self._lock:
            if self._closed:
                raise BrowserFetchUnavailable("browser-fetch: служба закрыта")
            process = self._ensure_process()
            request_id = next(self._ids)
            process.pending[request_id] = future
            line = json.dumps({"id": request_id, **request}, separators=(",", ":")) + "\n"
            try:
                assert process.proc.stdin is not None
                process.proc.stdin.write(line.encode("utf-8"))
                process.proc.stdin.flush()
            except OSError as exc:
                process.pending.pop(request_id, None)
                self._process = None
                raise BrowserFetchError(f"browser-fetch: процесс недоступен: {exc}") from exc
        return future

    def _ensure_process(self) -> _Process:
        current = self._process
        if current is not None and current.proc.poll() is None:
            return current
        executable = self._executable()
        if not executable.is_file():
            raise BrowserFetchUnavailable(f"browser-fetch: нет ядра {executable}")
        try:
            proc = subprocess.Popen(
                self._launcher(executable),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(executable.parent),
                creationflags=_CREATE_NO_WINDOW,
            )
        except OSError as exc:
            raise BrowserFetchUnavailable(f"browser-fetch: ядро не запускается: {exc}") from exc
        process = _Process(proc)
        self._process = process
        threading.Thread(target=self._read, args=(process,), name="browser-fetch", daemon=True).start()
        return process

    def _read(self, process: _Process) -> None:
        stdout = process.proc.stdout
        assert stdout is not None
        for raw in stdout:
            try:
                reply = json.loads(raw)
            except ValueError:
                continue
            with self._lock:
                future = process.pending.pop(int(reply.get("id") or 0), None)
            if future is not None and not future.done():
                future.set_result(reply)
        with self._lock:
            orphans = list(process.pending.values())
            process.pending.clear()
            if self._process is process:
                self._process = None
        for future in orphans:
            if not future.done():
                future.set_exception(BrowserFetchError("browser-fetch: процесс завершился"))

    @staticmethod
    def _stop(process: _Process) -> None:
        try:
            if process.proc.stdin is not None:
                process.proc.stdin.close()
            process.proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            process.proc.kill()


SERVICE = BrowserFetchService()
