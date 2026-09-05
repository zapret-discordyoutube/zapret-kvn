"""Stable navigation hosts that construct their page only on first use."""
from collections import OrderedDict, deque
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout


class DeferredSignal:
    def __init__(self):
        self.connections = []
        self.bound = None

    def connect(self, slot):
        if self.bound is not None:
            self.bound.connect(slot)
        else:
            self.connections.append(slot)

    def bind(self, signal):
        self.bound = signal
        for slot in self.connections:
            signal.connect(slot)
        self.connections.clear()


class DeferredPage(QWidget):
    created = pyqtSignal()
    def __init__(self, page_type, route, parent=None):
        super().__init__(parent)
        self.setObjectName(route)
        self._page_type = page_type
        self._page = None
        self._signals = {}
        self._pending = OrderedDict()
        self._logs = deque(maxlen=2000)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

    def ensure_page(self):
        if self._page is not None:
            return self._page
        self._page = self._page_type(self)
        self.layout().addWidget(self._page)
        for name, signal in self._signals.items():
            signal.bind(getattr(self._page, name))
        # Connections already exist; replaying snapshots must not save view prefs.
        suppress = getattr(self._page, "_suppress_pref_signals", None)
        if suppress is not None:
            self._page._suppress_pref_signals = True
        try:
            priority = {"apply_view_settings": -4, "set_subscriptions": -3, "set_nodes": -2, "set_active_node": -1}
            pending = sorted(self._pending.values(), key=lambda entry: priority.get(entry[0], 0 if entry[0].startswith("set_") else 1))
            for name, args, kwargs in pending:
                getattr(self._page, name)(*args, **kwargs)
            for line in self._logs:
                self._page.append_line(line)
        finally:
            if suppress is not None:
                self._page._suppress_pref_signals = suppress
            self._pending.clear()
            self._logs.clear()
        self.created.emit()
        return self._page

    def showEvent(self, event):
        self.ensure_page()
        super().showEvent(event)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        page = self.__dict__.get("_page")
        if page is not None:
            return getattr(page, name)
        page_type = self.__dict__.get("_page_type")
        if page_type is None:
            raise AttributeError(name)
        attr = getattr(page_type, name, None)
        if isinstance(attr, pyqtSignal):
            return self._signals.setdefault(name, DeferredSignal())
        if name == "append_line":
            return self._logs.append
        if name == "clear_view":
            return self._logs.clear
        if callable(attr) and (name.startswith(("set_", "update_", "finish_", "start_", "refresh_", "show_")) or name == "apply_view_settings"):
            def cache(*args, **kwargs):
                if self._page is not None:
                    return getattr(self._page, name)(*args, **kwargs)
                # Per-core/per-node updates must not overwrite each other.
                key = (name, args[0] if args and isinstance(args[0], str) else None)
                self._pending.pop(key, None)
                self._pending[key] = (name, args, kwargs)
                # Most recent state is bounded even while a page is never opened.
                if len(self._pending) > 12000:
                    self._pending.popitem(last=False)
            return cache
        return getattr(self.ensure_page(), name)
