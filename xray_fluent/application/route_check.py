"""«Проверить сайт» на странице правил: разбор маршрута вне GUI-потока.

Порядок правил повторяет :func:`route_explain.explain_route`, наборы правил
проверяет само ядро (``sing-box rule-set match``), адрес сайта — системный DNS
(в TUN он идёт через ядро, fakeip в стоковом конфиге нет). Один рабочий поток
и номер поколения, как у «Проверить» (:class:`SingboxEditorCheck`): устаревший
ответ отбрасывается.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import uuid

from PyQt6.QtCore import QObject, pyqtSignal

from ..constants import RUNTIME_DIR, SINGBOX_PATH_DEFAULT
from ..profiles.path_utils import resolve_configured_path
from ..singbox_config.route_explain import RouteVerdict, explain_route

_MATCH_MARK = "match rules.["
_INLINE_VERSION = 3


def rule_set_match_command(exe: Path, definition: dict, value: str, *, inline_path: Path | None = None) -> list[str] | None:
    """Команда ``sing-box rule-set match`` для набора или ``None``, если проверить нельзя.

    ``-f`` передаётся всегда: без него ядро считает файл исходником JSON и
    бинарный ``.srs`` не читает. Относительный путь — от папки ядра, как при запуске.
    """
    kind = definition.get("type") or "inline"
    if kind == "local":
        raw = str(definition.get("path") or "")
        if not raw:
            return None
        path = Path(raw)
        if not path.is_absolute():
            path = exe.parent / path
        fmt = definition.get("format") or ("binary" if path.suffix.lower() == ".srs" else "source")
        return [str(exe), "rule-set", "match", "-f", str(fmt), str(path), value]
    if kind == "inline" and inline_path is not None:
        return [str(exe), "rule-set", "match", "-f", "source", str(inline_path), value]
    return None  # набор по URL лежит только в кэше ядра


class RuleSetMatcher:
    """Ответы ядра по наборам с кэшем на одну проверку."""

    def __init__(self, exe: Path, runtime_dir: Path, run=None):
        from ..platform.windows.subprocess_utils import CREATE_NO_WINDOW, decode_output, run_text

        self._exe = exe
        self._runtime_dir = runtime_dir
        self._run = run or (lambda command: run_text(command, timeout=15.0, creationflags=CREATE_NO_WINDOW or None))
        # Go println пишет в stderr; читаем оба потока.
        self._output = lambda done: decode_output(done.stdout or b"") + decode_output(done.stderr or b"")
        self._cache: dict[tuple[str, str], bool | None] = {}
        self._inline: list[Path] = []

    def _inline_file(self, definition: dict) -> Path:
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        path = self._runtime_dir / f"route_check_{uuid.uuid4().hex}.json"
        payload = {"version": _INLINE_VERSION, "rules": definition.get("rules") or []}
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        self._inline.append(path)
        return path

    def __call__(self, definition: dict, value: str) -> bool | None:
        key = (str(definition.get("tag")), value)
        if key in self._cache:
            return self._cache[key]
        inline = self._inline_file(definition) if (definition.get("type") or "inline") == "inline" else None
        command = rule_set_match_command(self._exe, definition, value, inline_path=inline)
        result: bool | None = None
        if command is not None and (inline is not None or Path(command[5]).is_file()):
            try:
                completed = self._run(command)
            except Exception:  # ядро не запустилось — ответа нет
                completed = None
            if completed is not None and completed.returncode == 0:
                result = _MATCH_MARK in self._output(completed)
        self._cache[key] = result
        return result

    def close(self) -> None:
        for path in self._inline:
            path.unlink(missing_ok=True)


def resolve_host(domain: str) -> list[str]:
    infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


class RouteCheck(QObject):
    #: ``(generation, verdict | None, error)``.
    finished = pyqtSignal(int, object, str)

    def __init__(self, parent: QObject | None = None, *, runtime_dir: Path = RUNTIME_DIR):
        super().__init__(parent)
        self._runtime_dir = runtime_dir
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="route_check")
        self._generation = 0

    def start(self, singbox_path: str, text: str, host: str, *, tun: bool) -> int:
        self._generation += 1
        generation = self._generation
        exe = resolve_configured_path(
            singbox_path,
            default_path=SINGBOX_PATH_DEFAULT,
            use_default_if_empty=True,
            migrate_default_location=True,
        )
        self._executor.submit(self._run, generation, exe, text, host, tun)
        return generation

    def _run(self, generation: int, exe: Path | None, text: str, host: str, tun: bool) -> None:
        # Рабочий поток: сигнал доставляется в GUI-поток через очередь.
        try:
            verdict = self.check_blocking(exe, text, host, tun=tun)
        except Exception as exc:  # ошибка не должна пропасть молча
            self.finished.emit(generation, None, f"{type(exc).__name__}: {exc}")
            return
        self.finished.emit(generation, verdict, "")

    def check_blocking(self, exe: Path | None, text: str, host: str, *, tun: bool, run=None) -> RouteVerdict:
        document = json.loads(text)
        matcher = RuleSetMatcher(exe, self._runtime_dir, run) if exe is not None and exe.is_file() else None
        try:
            return explain_route(
                document,
                host,
                tun=tun,
                match_set=matcher if matcher is not None else (lambda _definition, _value: None),
                resolve=resolve_host,
            )
        finally:
            if matcher is not None:
                matcher.close()

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
