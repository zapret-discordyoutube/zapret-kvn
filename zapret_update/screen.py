"""Что на экране: игра, видео или презентация во весь экран — одно правило для обеих программ.

Обновление перезапускает программу и на несколько секунд останавливает обход
(у Zapret 2 GUI) или подключение (у Zapret KVN): посреди игры это вылет из
матча. Поэтому программа, которая обновляется сама, спрашивает здесь, не на
весь ли экран у человека игра, — сейчас или в последние минуты.

Признаки (ответ Windows ``SHQueryUserNotificationState`` и окно на переднем
плане) уходят серверу общим счётом (``screen_state``): по нему видно,
насколько правилу можно верить. Живая статистика 2026-10-15: игры в режиме
«окно без рамки» Windows называет обычными окнами («можно», 5) — их выдаёт
само окно на весь экран без заголовка и рамки.

Только стандартная библиотека (ctypes), без Qt: зовут и из потоков.
"""

from __future__ import annotations

import sys
import threading
import time

# Ответы Windows на вопрос «можно ли сейчас показывать уведомления»
# (SHQueryUserNotificationState).
_QUNS_NOT_PRESENT = 1  # экран заблокирован, заставка, сеанс отключён — человек отошёл
_QUNS_BUSY = 2
_QUNS_RUNNING_D3D_FULL_SCREEN = 3
_QUNS_PRESENTATION_MODE = 4
_QUNS_APP = 7  # полноэкранное приложение из Microsoft Store
# Игра Direct3D на весь экран и режим презентации — ответы однозначные.
_SURE_STATES = (_QUNS_RUNNING_D3D_FULL_SCREEN, _QUNS_PRESENTATION_MODE)

# Что стоит на переднем плане.
FOREGROUND_FULL = "f"     # чужое окно закрывает весь экран
FOREGROUND_BARE = "b"     # чужое окно на весь экран без заголовка и рамки: игра или видео
FOREGROUND_PART = "p"     # окно занимает часть экрана
FOREGROUND_SHELL = "s"    # рабочий стол или панель задач
FOREGROUND_OWN = "o"      # окно самой программы
_SHELL_CLASSES = ("Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd")


def _notification_state() -> int:
    """Состояние экрана по мнению Windows; 0 — узнать не удалось."""
    if sys.platform != "win32":
        return 0
    try:
        import ctypes

        state = ctypes.c_int(0)
        if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) != 0:
            return 0
        return int(state.value)
    except Exception:
        return 0


def _foreground() -> str:
    """Что на переднем плане: одна буква ``FOREGROUND_*`` либо пусто — не узнать."""
    if sys.platform != "win32":
        return ""
    try:
        import ctypes
        import os
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        window = user32.GetForegroundWindow()
        if not window:
            return FOREGROUND_SHELL
        name = ctypes.create_unicode_buffer(64)
        user32.GetClassNameW(window, name, 64)
        if name.value in _SHELL_CLASSES:
            return FOREGROUND_SHELL
        owner = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == os.getpid():
            return FOREGROUND_OWN

        class _MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        rect = wintypes.RECT()
        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(_MonitorInfo)
        monitor = user32.MonitorFromWindow(window, 2)  # ближайший к окну экран
        if not user32.GetWindowRect(window, ctypes.byref(rect)) or not user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            return ""
        screen = info.rcMonitor
        covers = (
            rect.left <= screen.left and rect.top <= screen.top
            and rect.right >= screen.right and rect.bottom >= screen.bottom
        )
        if not covers:
            return FOREGROUND_PART
        # Без заголовка и рамки окно на весь экран — это игра в режиме «окно
        # без рамки» или видео на весь экран. Обычное развёрнутое окно (при
        # скрытой панели задач оно тоже закрывает весь экран) с заголовком.
        style = int(user32.GetWindowLongW(window, -16)) & 0xFFFFFFFF  # GWL_STYLE
        captioned = (style & 0x00C00000) == 0x00C00000  # WS_CAPTION
        sizable = bool(style & 0x00040000)  # WS_THICKFRAME
        return FOREGROUND_FULL if captioned or sizable else FOREGROUND_BARE
    except Exception:
        return ""


def is_fullscreen(state: int, foreground: str) -> bool:
    """Занят ли экран игрой, видео или презентацией — по двум независимым признакам.

    Игра Direct3D на весь экран и режим презентации — ответы Windows
    однозначные. Ответ «экран занят» (2) расплывчат: его дают и невидимые
    окна поверх экрана, и чужие оболочки. Ему (и полноэкранному приложению
    Store, 7) программа верит, только если окно на переднем плане и правда
    закрывает весь экран и это не рабочий стол и не она сама.

    Игры в режиме «окно без рамки» Windows считает обычными окнами и отвечает
    «можно» (5) — так было у ~5 % программо-минут. Их выдаёт само окно: на
    весь экран, без заголовка и рамки. Если человек отошёл (1), обновлению
    ничто не мешает.
    """
    if state == _QUNS_NOT_PRESENT:
        return False
    if state in _SURE_STATES or foreground == FOREGROUND_BARE:
        return True
    return state in (_QUNS_BUSY, _QUNS_APP) and foreground in (FOREGROUND_FULL, FOREGROUND_BARE)


def screen_state() -> str:
    """Оба признака одной строкой, например ``2f`` или ``5p``: код ответа
    Windows и что на переднем плане. Уходит серверу общим счётом — по нему
    видно, насколько правилу «занят» можно верить."""
    state = _notification_state()
    return f"{state}{_foreground()}" if state else ""


# Память об игре: человек свернул игру и ушёл в Discord — на переднем плане
# уже не игра, но обновление на несколько секунд остановит обход и выкинет
# его из игры. Поэтому занятым он считается ещё столько после того, как
# игру на весь экран видели в последний раз.
GAME_MEMORY_SECONDS = 10 * 60
# Как часто фоновая проверка смотрит на экран (дёшево: два вызова Windows).
SAMPLE_SECONDS = 10.0

_memory_lock = threading.Lock()
_last_fullscreen = 0.0
_sampler: threading.Thread | None = None


def _note_fullscreen(now: float) -> None:
    global _last_fullscreen
    with _memory_lock:
        _last_fullscreen = now


def _recently_fullscreen(now: float) -> bool:
    with _memory_lock:
        return _last_fullscreen > 0 and now - _last_fullscreen < GAME_MEMORY_SECONDS


def fullscreen_active(*, now: float | None = None) -> bool:
    """На экране игра, видео или презентация во весь экран — сейчас или недавно."""
    moment = time.monotonic() if now is None else now
    state = _notification_state()
    if state == _QUNS_NOT_PRESENT:
        # Экран заблокирован: человек отошёл, обновиться самое время.
        return False
    foreground = _foreground() if state not in _SURE_STATES else ""
    if is_fullscreen(state, foreground):
        _note_fullscreen(moment)
        return True
    return _recently_fullscreen(moment)


def _sample_forever() -> None:
    while True:
        try:
            fullscreen_active()
        except Exception:
            pass
        time.sleep(SAMPLE_SECONDS)


def start_sampler() -> None:
    """Фоновая проверка экрана раз в ``SAMPLE_SECONDS``: память об игре без пропусков."""
    global _sampler
    if sys.platform != "win32":
        return
    with _memory_lock:
        if _sampler is not None:
            return
        _sampler = threading.Thread(target=_sample_forever, name="busy-sampler", daemon=True)
        _sampler.start()


__all__ = [
    "FOREGROUND_BARE",
    "FOREGROUND_FULL",
    "FOREGROUND_OWN",
    "FOREGROUND_PART",
    "FOREGROUND_SHELL",
    "GAME_MEMORY_SECONDS",
    "fullscreen_active",
    "is_fullscreen",
    "screen_state",
    "start_sampler",
]
