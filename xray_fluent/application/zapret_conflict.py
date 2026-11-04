"""Самопроверка: не мешает ли Zapret туннелю VPN (TUN) — и что делать, если мешает.

Встроенный Zapret (winws2 через WinDivert) и туннель режима TUN перехватывают одни и те же
пакеты; на части компьютеров, особенно когда рядом работает ещё и Zapret 2 GUI, трафик через
туннель перестаёт идти. После каждого подключения TUN приложение один раз:

1. ищет Zapret из другой папки и только предупреждает о нём (чужие процессы не трогаются);
2. если работает свой winws2 без правила для VPN-сервера (остановка не опасна для сессии),
   проверяет туннель настоящим запросом. Не открылся (два раза) — останавливает свой winws2
   и проверяет снова. Открылся — мешал Zapret: автозапуск выключается и сохраняется, человек
   получает объяснение. Не открылся и без него — виноват не Zapret, winws2 возвращается.

Всё, что трогает контроллер и менеджер Zapret (живут в GUI-потоке), идёт запросом в GUI-поток.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, pyqtSignal

from ..engines.zapret.foreign import foreign_zapret_processes
from ..engines.zapret.manager import WINWS2_EXE, WINWS_EXE
from ..network.fetch_diagnosis import CONTROL_HOST, probe_direct

if TYPE_CHECKING:
    from .controller import AppController

_LOG = logging.getLogger(__name__)

FOREIGN_NOTICE = (
    "Рядом запущен Zapret из другой папки ({names}), возможно Zapret 2 GUI. В режиме VPN (TUN) две программы "
    "перехватывают одни и те же пакеты, и трафик через туннель может не идти. Если на «Панели» трафик нулевой "
    "или сайты открываются с перебоями, закройте тот Zapret или переключитесь на режим «Прокси». "
    "ZapretKVN чужие процессы сам не останавливает."
)
CONFLICT_NOTICE = (
    "Встроенный Zapret мешал туннелю: через VPN ничего не открывалось, а без Zapret открывается. "
    "Zapret остановлен, его автозапуск выключен, и сам он не включится. Включить снова можно на странице Zapret."
)


CRASH_HINT = (
    " Рядом работает Zapret из другой папки ({names}): в режиме VPN (TUN) такие программы перехватывают одни "
    "и те же пакеты и могут ронять ядро. Закройте тот Zapret или используйте режим «Прокси»."
)


def foreign_crash_hint(finder: Callable[[], list[str]] | None = None) -> str:
    """Подсказка к аварии ядра в режиме TUN, если рядом работает чужой Zapret; иначе пустая строка."""

    try:
        names = (finder or ZapretConflictCheck._find_foreign)()
    except Exception:  # noqa: BLE001 — подсказка не должна ломать разбор аварии
        return ""
    return CRASH_HINT.format(names=", ".join(names)) if names else ""


class _Call:
    """Запрос рабочего потока в GUI-поток: действие, аргумент и ответ."""

    def __init__(self, arg: Any = None) -> None:
        self.arg = arg
        self.result: Any = None
        self.event = threading.Event()


def tunnel_probe() -> bool:
    """Открывается ли контрольный сайт по обычному пути: в режиме TUN это путь через туннель."""

    return bool(probe_direct(CONTROL_HOST, 443).ok)


class ZapretConflictCheck(QObject):
    request = pyqtSignal(str, object)

    def __init__(
        self,
        controller: AppController,
        *,
        probe: Callable[[], bool] = tunnel_probe,
        finder: Callable[[], list[str]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        settle_s: float = 3.0,
        retry_pause_s: float = 2.0,
        stop_pause_s: float = 2.0,
    ) -> None:
        super().__init__(controller)
        self._controller = controller
        self._probe = probe
        self._finder = finder or self._find_foreign
        self._sleep = sleep
        self._settle_s = settle_s
        self._retry_pause_s = retry_pause_s
        self._stop_pause_s = stop_pause_s
        self._generation = 0
        self._busy = False
        self._warned_foreign = False
        self._saved_plan: Any = None
        self.last_outcome = ""
        self.request.connect(self._on_request)

    # ── запуск ────────────────────────────────────────────────

    def on_connection_changed(self, connected: bool) -> None:
        """Подключено — запустить проверку; отключено — отменить идущую."""

        self._generation += 1
        if not connected or self._busy:
            return
        session = self._controller._active_session
        if session is None or not session.tun_mode:
            return
        self._busy = True
        threading.Thread(
            target=self._run, args=(self._generation,), name="zapret-conflict-check", daemon=True
        ).start()

    def _run(self, generation: int) -> None:
        try:
            self.last_outcome = self._sequence(generation)
            _LOG.info("zapret-check: итог %s", self.last_outcome)
        except Exception:  # noqa: BLE001 — проверка не должна ничего ломать
            _LOG.exception("zapret-check: сбой проверки")
            self.last_outcome = "error"
        finally:
            self._busy = False

    # ── сама проверка (рабочий поток) ─────────────────────────────────

    def _sequence(self, generation: int) -> str:
        self._sleep(self._settle_s)
        if not self._call("valid", generation):
            return "cancelled"
        names = self._finder()
        if names and not self._warned_foreign:
            self._warned_foreign = True
            self._call("notice_foreign", names)
        state = self._call("own_state")
        if state != "stoppable":
            return f"own-{state or 'not-running'}" + ("+foreign" if names else "")
        if self._probe():
            return "ok"
        self._sleep(self._retry_pause_s)
        if self._probe():
            return "ok"
        if not self._call("valid", generation):
            return "cancelled"
        self._call("stop_own")
        conflict = False
        try:
            self._sleep(self._stop_pause_s)
            conflict = bool(self._call("valid", generation) and self._probe())
        finally:
            # Что бы ни случилось с проверкой, остановленный ради неё winws2 не должен остаться остановленным.
            if not conflict:
                self._call("restore_own")
        if conflict:
            self._call("disable")
            return "conflict"
        return "not-zapret"

    def _call(self, action: str, arg: Any = None) -> Any:
        call = _Call(arg)
        self.request.emit(action, call)
        call.event.wait(20.0)
        return call.result

    @staticmethod
    def _find_foreign() -> list[str]:
        found = foreign_zapret_processes([WINWS2_EXE, WINWS_EXE])
        names: list[str] = []
        for _pid, path in found:
            name = path.replace("\\", "/").rsplit("/", 1)[-1] if path else "winws"
            if name not in names:
                names.append(name)
        return names

    # ── действия в GUI-потоке ─────────────────────────────────────

    def _on_request(self, action: str, call: _Call) -> None:
        try:
            call.result = self._handle(action, call.arg)
        except Exception:  # noqa: BLE001
            _LOG.exception("zapret-check: действие %s не удалось", action)
            call.result = None
        finally:
            call.event.set()

    def _handle(self, action: str, arg: Any) -> Any:
        controller = self._controller
        if action == "valid":
            session = controller._active_session
            return bool(
                controller.connected
                and not controller.locked
                and arg == self._generation
                and session is not None
                and session.tun_mode
            )
        if action == "notice_foreign":
            text = FOREIGN_NOTICE.format(names=", ".join(arg))
            controller._log(f"[zapret] {text}")
            controller.status.emit("warning-long", text)
            return True
        if action == "own_state":
            zapret = controller.zapret
            if not zapret.running or zapret.plan is None:
                return None
            if zapret.rule is not None or controller.bypass.required(controller.selected_node):
                # Эта сессия держится на правиле winws2: его остановка по правилам проекта оборвёт VPN.
                return "carries-rule"
            self._saved_plan = zapret.plan
            return "stoppable"
        if action == "stop_own":
            controller._log("[zapret] проверка туннеля не прошла: свой winws2 остановлен на время проверки")
            controller.zapret.stop()
            return True
        if action == "restore_own":
            plan, self._saved_plan = self._saved_plan, None
            if plan is not None and controller.connected:
                controller._log("[zapret] туннель не открывается и без Zapret: winws2 возвращён")
                controller.zapret.apply(plan)
            return True
        if action == "disable":
            self._saved_plan = None
            settings = controller.state.settings
            settings.zapret_autostart = False
            controller._log("[zapret] Zapret мешал туннелю: автозапуск выключен")
            controller.save()
            controller.settings_changed.emit(settings)
            controller.status.emit("warning-long", CONFLICT_NOTICE)
            return True
        raise ValueError(action)


__all__ = ["CONFLICT_NOTICE", "CRASH_HINT", "FOREIGN_NOTICE", "ZapretConflictCheck", "foreign_crash_hint", "tunnel_probe"]
