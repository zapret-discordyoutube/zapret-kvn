"""Сигнал сервера о новой версии: «длинный запрос».

Программа спрашивает сервер: «я на версии X — есть новее?». Сервер не
отвечает, пока новой версии нет, и отвечает в момент её выхода. Так
обновление приходит за минуты, а не при очередной проверке раз в полчаса.

Сигнал — это ещё и разрешение. Если все программы пойдут за архивом в 140 МБ
разом, сервер встанет, поэтому очередь на скачивание ведёт он: «можно
обновляться» говорит в меру своего канала, остальным — «вы в очереди»
(``queued``; место хранит «талон», который программа называет в следующих
вопросах). Новую версию сервер раздаёт по ступеням: сначала малой доле
программ, остальным — когда первые обновились и снова вышли на связь
(``held``). Если версия не ставится, раздача останавливается сама.

Вместе с вопросом программа называет одно слово о себе (окно открыто, в трее,
на экране игра) и включено ли подключение, а после обновления — с какой
версии пришла и сколько оно заняло. Адресов, имён и настроек в вопросе нет.

Ответ несёт только номер версии. Откуда качать и какая у архива контрольная
сумма, программа по-прежнему узнаёт сама у Forgejo: ложный сигнал ничего
установить не может.

Сервера с очередью может не быть (старый сервер, блокировка): тогда
программа живёт как раньше и проверяет обновления сама.

Модуль не импортирует Qt: слушатель работает в своём фоновом потоке.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections.abc import Callable
from urllib.parse import urlencode
from urllib.request import Request

from ..network.http_utils import urlopen
from .app_updater import USER_AGENT, _is_newer_version, _parse_semver

_log = logging.getLogger(__name__)

WAIT_URL = "https://git.zapret.moe/api/zapret/kvn/wait"
CHANNEL = "stable"

# Вопрос без ожидания: сервер отвечает сразу — так видно, что он на месте.
PROBE_TIMEOUT_S = 15
# Сервер держит вопрос до четырёх с половиной минут; ждём немного дольше.
READ_TIMEOUT_S = 330
# Честный ответ «новостей нет» приходит не раньше срока ожидания. Быстрый
# пустой ответ — признак неисправности: без паузы слушатель завалил бы сервер.
QUICK_ANSWER_S = 20.0
QUICK_ANSWER_PAUSE_S = 120.0
FIRST_FAILURE_PAUSE_S = 60.0
MAX_FAILURE_PAUSE_S = 15 * 60.0
DISABLED_RECHECK_S = 60.0
# Занятая программа спрашивает короче: освободилась — и через минуту уже
# просит разрешение по-настоящему.
BUSY_HOLD_S = 60
# В первые минуты после запуска состояние быстро меняется (подключение ещё
# поднимается), поэтому вопрос держится недолго — иначе сервер несколько
# минут помнил бы состояние первых секунд.
WARMUP_S = 120.0
WARMUP_HOLD_S = 45

ACTIVITY_WINDOW = "window"
ACTIVITY_TRAY = "tray"
ACTIVITY_FULLSCREEN = "fullscreen"

# Ответы Windows на вопрос «можно ли сейчас показывать уведомления»
# (SHQueryUserNotificationState): окно на весь экран, игра Direct3D на весь
# экран, режим презентации.
_FULLSCREEN_STATES = (2, 3, 4)


def fullscreen_app_active() -> bool:
    """На экране игра, видео или презентация во весь экран.

    Обновление перезапускает программу и на несколько секунд рвёт
    подключение: посреди игры это вылет из матча.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        state = ctypes.c_int(0)
        if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) != 0:
            return False
        return int(state.value) in _FULLSCREEN_STATES
    except Exception:
        return False


def _ask_server(url: str, timeout: float) -> dict:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("сервер ответил не тем, чего ждал слушатель")
    return payload


class ReleaseWatcher:
    """Ждёт разрешение сервера обновиться и сообщает о нём один раз на версию.

    ``on_release(version)`` и ``on_queued(version)`` вызываются из фонового
    потока слушателя. ``activity()`` возвращает ``{"act": ..., "run": ...}``,
    ``pending_report()`` — ``{"prev", "took"}`` либо ``{"fail"}`` для одного
    сообщения серверу; после доставки зовётся ``report_delivered``.
    """

    def __init__(
        self,
        *,
        current_version: str,
        on_release: Callable[[str], None],
        on_queued: Callable[[str], None] = lambda _version: None,
        is_enabled: Callable[[], bool] = lambda: True,
        is_busy: Callable[[], bool] = fullscreen_app_active,
        activity: Callable[[], dict] = dict,
        pending_report: Callable[[], dict] = dict,
        report_delivered: Callable[[dict], None] = lambda _report: None,
        ask: Callable[[str, float], dict] = _ask_server,
        url: str = WAIT_URL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._known = str(current_version).lstrip("vV")
        self._on_release = on_release
        self._on_queued = on_queued
        self._is_enabled = is_enabled
        self._is_busy = is_busy
        self._activity = activity
        self._pending_report = pending_report
        self._report_delivered = report_delivered
        self._ask_server = ask
        self._url = url
        self._clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Ответил ли сервер: None — ещё не знаем, идёт первый вопрос.
        self._reachable: bool | None = None
        self._probed = False
        self._queued_version = ""
        self._ticket = 0
        self._held = ""
        self._started_at: float | None = None

    @property
    def reachable(self) -> bool | None:
        """True — сервер ведёт очередь обновлений для этой программы."""
        return self._reachable

    @property
    def known_version(self) -> str:
        return self._known

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self.run, name="update-release-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _pause(self, seconds: float) -> bool:
        """Пауза, которую прерывает остановка. True — пора выходить."""
        return self._stop.wait(max(float(seconds), 0.0))

    def _call(self, callback: Callable, default):
        try:
            return callback()
        except Exception:
            return default

    def run(self) -> None:
        if _parse_semver(self._known) is None:
            # Сборка без нормальной версии сравнивать ничего не может.
            self._reachable = False
            return
        failures = 0
        while not self._stop.is_set():
            if not self._call(self._is_enabled, False):
                self._reachable = False
                self._probed = False
                if self._pause(DISABLED_RECHECK_S):
                    return
                continue
            probe = not self._probed
            started = self._clock()
            try:
                answer = self._ask(probe=probe)
            except Exception as exc:
                self._probed = False
                self._reachable = False
                failures += 1
                if failures == 1:
                    _log.info("[update] Очередь обновлений на сервере недоступна (%s): программа проверяет сама", exc)
                if self._pause(min(FIRST_FAILURE_PAUSE_S * 2 ** (failures - 1), MAX_FAILURE_PAUSE_S)):
                    return
                continue
            failures = 0
            self._reachable = True
            if probe:
                self._probed = True
                _log.info("[update] Ждём сигнал сервера о новой версии")
            if self._stop.is_set():
                return
            allowed = self._accept(answer)
            if probe or allowed:
                continue
            if self._clock() - started < QUICK_ANSWER_S and self._pause(QUICK_ANSWER_PAUSE_S):
                return

    def _ask(self, *, probe: bool) -> dict:
        params = {"channel": CHANNEL, "known": self._known}
        busy = bool(self._call(self._is_busy, False))
        if self._started_at is None:
            self._started_at = self._clock()
        if probe:
            params["hold"] = "0"
        elif self._clock() - self._started_at < WARMUP_S:
            params["hold"] = str(WARMUP_HOLD_S)
        elif busy:
            params["hold"] = str(BUSY_HOLD_S)
        if busy:
            params["busy"] = "1"
        if self._ticket:
            # С талоном программа стоит по времени первой постановки, а не
            # уходит в конец очереди при каждом новом вопросе.
            params["ticket"] = str(self._ticket)
        told = self._call(self._activity, {})
        if isinstance(told, dict):
            params.update({key: str(told[key]) for key in ("act", "run") if told.get(key) not in (None, "")})
        report = self._call(self._pending_report, {})
        report = {str(key): str(value) for key, value in report.items()} if isinstance(report, dict) else {}
        params.update(report)
        answer = self._ask_server(f"{self._url}?{urlencode(params)}", PROBE_TIMEOUT_S if probe else READ_TIMEOUT_S)
        if report:
            self._call(lambda: self._report_delivered(report), None)
        return answer

    def _newer_version(self, answer: dict) -> str:
        version = str(answer.get("version") or "").lstrip("vV")
        if _parse_semver(version) is None or not _is_newer_version(version, self._known):
            return ""
        return version

    def _accept(self, answer: dict) -> bool:
        """True — сервер разрешил обновиться до версии новее известной."""
        version = self._newer_version(answer)
        if not version:
            return False
        if answer.get("changed"):
            # Запоминаем до вызова: об одной версии разрешение приходит один раз.
            self._known = version
            self._queued_version = ""
            self._ticket = 0
            _log.info("[update] Сервер разрешил обновиться до v%s", version)
            self._notify(self._on_release, version)
            return True
        if answer.get("queued"):
            if self._queued_version != version:
                self._ticket = 0
            if not self._ticket:
                try:
                    self._ticket = max(int(answer.get("ticket") or 0), 0)
                except (TypeError, ValueError):
                    self._ticket = 0
            if self._queued_version != version:
                self._queued_version = version
                _log.info("[update] Вышла версия v%s: ждём очереди на скачивание", version)
                self._notify(self._on_queued, version)
            return False
        held = str(answer.get("held") or "")
        if held and self._held != f"{held}:{version}":
            self._held = f"{held}:{version}"
            reason = {
                "stage": "сервер раздаёт её по ступеням, очередь этой программы ещё не подошла",
                "halted": "сервер остановил её раздачу",
                "busy": "программа занята — обновится, когда освободится",
            }.get(held, "сервер просит подождать")
            _log.info("[update] Вышла версия v%s: %s", version, reason)
        return False

    @staticmethod
    def _notify(callback: Callable[[str], None], version: str) -> None:
        try:
            callback(version)
        except Exception:
            _log.warning("[update] Сигнал о версии v%s не обработан", version, exc_info=True)
