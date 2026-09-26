"""Детерминированное завершение Qt: окна разрушаются, пока жив ``QApplication``.

Если оставить окна сборщику мусора, их C++-деструкторы срабатывают при
финализации интерпретатора в неопределённом порядке, иногда уже после
``QApplication``, и процесс падает на выходе (segfault / access violation).
Надеяться, что GC успеет раньше, нельзя: qfluentwidgets подключает к
глобальному ``qconfig.themeChanged`` лямбды, замкнутые на виджет
(``FluentLabelBase._init``), и такие обёртки живут до разрушения ``qconfig``.

Окно, у которого ещё работает дочерний ``QThread`` или ``QProcess``, не
удаляется: разрушение живого потока — ``qFatal``, а ``~QProcess`` убивает
процесс и ждёт его. Такое окно остаётся прежнему порядку выхода.
"""

from __future__ import annotations

import gc
import logging

from PyQt6 import sip
from PyQt6.QtCore import QProcess, QThread
from PyQt6.QtWidgets import QApplication, QWidget


def dispose_windows(windows: list[QWidget], logger: logging.Logger | None = None) -> list[QWidget]:
    """Удаляет окна из ``windows``; возвращает те, что пришлось оставить.

    На время каскада C++-деструкторов циклический GC выключен: иначе он может
    собрать Python-обёртку виджета, который как раз разрушается (так падали
    Windows-тесты при пакетном удалении страниц, см. test_app_scrollable_page).
    """
    kept: list[QWidget] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for window in windows:
            if sip.isdeleted(window):
                continue
            running = [thread for thread in window.findChildren(QThread) if thread.isRunning()]
            running += [
                process for process in window.findChildren(QProcess)
                if process.state() != QProcess.ProcessState.NotRunning
            ]
            if running:
                if logger is not None:
                    logger.warning(
                        "Window kept until interpreter exit: %d background thread(s)/process(es) still running: %s",
                        len(running),
                        ", ".join(type(item).__name__ for item in running),
                    )
                kept.append(window)
                continue
            window.hide()
            sip.delete(window)
    finally:
        if gc_was_enabled:
            gc.enable()
    windows[:] = kept
    gc.collect()
    return kept


def dispose_all_widgets(windows: list[QWidget], logger: logging.Logger | None = None) -> list[QWidget]:
    """Сначала главные окна, затем все оставшиеся виджеты верхнего уровня.

    Вторым проходом уходят меню трея без родителя, всплывающие подсказки и
    прочие окна qfluentwidgets, которые иначе дожили бы до финализации.
    """
    kept = dispose_windows(windows, logger)
    app = QApplication.instance()
    if app is not None:
        rest = [widget for widget in app.topLevelWidgets() if not any(widget is k for k in kept)]
        kept += dispose_windows(rest, logger)
    return kept
