"""Observe a bounded probe wave without blocking the Qt thread."""
from PyQt6.QtCore import QObject, QTimer


class BackgroundHealthCheck(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._executor = None
        self._futures = {}
        self._failures = {}
        self._current = None
        self._complete = None
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self.poll)

    @property
    def active(self):
        return self._executor is not None

    def adopt(self, executor, futures, failures, *, current, complete):
        self.cancel()
        self._executor = executor
        self._futures = dict(futures)
        self._failures = dict(failures)
        self._current = current
        self._complete = complete
        self._timer.start()

    def cancel(self):
        self._timer.stop()
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
        self._executor = None
        self._futures.clear()
        self._failures.clear()
        self._current = self._complete = None

    def poll(self):
        if not self.active:
            return
        if not self._current():
            self.cancel()
            return
        winner = None
        for future in list(self._futures):
            if not future.done():
                continue
            host = self._futures.pop(future)
            if future.cancelled():
                self._failures[host] = "cancelled"
                continue
            error = future.exception()
            if error is None:
                winner = host
                break
            self._failures[host] = f"{type(error).__name__}: {error}"
        if winner is None and self._futures:
            return
        complete, failures = self._complete, dict(self._failures)
        self.cancel()
        complete(winner, failures)
