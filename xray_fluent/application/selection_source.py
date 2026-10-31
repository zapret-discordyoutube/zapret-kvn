"""Источник смены выбранного сервера.

Каждая смена ``state.selected_node_id`` называет свой источник и пишет в лог
одну строку ``[select] source=…``.  Без этого явное действие пользователя
(кнопка «Следующий», трей, таблица) в диагностике неотличимо от сбоя
программы: инцидент 28.09.2026 — в логе был только ``[core-switch]`` без
причины.

Модуль-лист без импортов проекта: его импортируют и application-, и UI-слой.
"""

from __future__ import annotations

from enum import Enum


class SelectionSource(Enum):
    """Кто сменил выбранный сервер.

    ``manual`` — выбор сделал пользователь: он сбрасывает учёт анти-дребезга
    авто-переключения и фиксирует сервер (manual hold).  Автоматические
    источники этот учёт не трогают.
    """

    # Явные действия пользователя.
    DASHBOARD_NEXT = ("dashboard-next", "кнопка «Следующий» на главной", True)
    TRAY_NEXT = ("tray-next", "трей → «Следующий сервер»", True)
    NODES_DOUBLE_CLICK = ("nodes-double-click", "двойной клик в таблице серверов", True)
    NODES_ENTER = ("nodes-enter", "Enter в таблице серверов", True)
    NODES_MENU = ("nodes-menu", "меню таблицы серверов → «Подключить»", True)
    NODES_IMPORTED = ("nodes-imported", "импорт серверов: выбран первый новый", True)
    # Автоматика.
    AUTO_SWITCH = ("auto-switch", "авто-переключение: сервер недоступен", False)
    SMART_SWITCH = ("smart-switch", "умная проверка: сервер медленный", False)
    ROTATION = ("rotation", "ротация серверов", False)
    HYSTERIA_RECOVERY = ("hysteria-recovery", "отказ Hysteria: резервный сервер", False)
    # Выбранный сервер исчез из списка — выбран первый оставшийся.
    NODE_REMOVED = ("node-removed", "выбранный сервер удалён", False)
    SUBSCRIPTION = ("subscription", "подписка: выбранного сервера больше нет", False)

    def __init__(self, code: str, label: str, manual: bool) -> None:
        self.code = code
        self.label = label
        self.manual = manual
