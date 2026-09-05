"""Two-phase startup preparation. Workers never construct Qt widgets/managers."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from PyQt6.QtCore import QObject, QThread, pyqtSignal
from ..profiles.models import AppState, AppSettings
from ..profiles.storage import StateStorage, PassphraseRequired
from ..diagnostics.traffic_history import TrafficHistoryStorage


class StartupWorker(QThread):
    early = pyqtSignal(object, bool)
    loaded = pyqtSignal(object, object)
    password_needed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, storage, prepare=None, parent=None):
        super().__init__(parent)
        self.storage = storage
        self.prepare = prepare

    def run(self):
        started = time.perf_counter()
        payload = None
        try:
            if not hasattr(self.storage, "_startup_raw"):
                self.storage._startup_raw = self.storage.state_file.read_text(encoding="utf-8") if self.storage.state_file.exists() else ""
            payload = self.storage.load_payload(self.storage._startup_raw)
            settings = AppSettings.from_dict(payload.get("settings") or {})
            locked = bool((payload.get("security") or {}).get("enabled"))
            self.early.emit(settings, locked)
            if self.isInterruptionRequested():
                return
            if self.prepare:
                self.prepare()
            state = self.storage._normalize_state_paths(AppState.from_dict(payload))
            history = TrafficHistoryStorage()
            if not self.isInterruptionRequested():
                self.loaded.emit(state, history)
        except PassphraseRequired:
            self.early.emit(AppSettings(), True)
            self.password_needed.emit()
        except Exception:
            if payload is None and self.storage.passphrase:
                self.password_needed.emit()
                return
            self.failed.emit("Не удалось загрузить данные приложения")
            logging.getLogger("xray_fluent.bootstrap").error("Startup data preparation failed")
        finally:
            logging.getLogger("xray_fluent.bootstrap").info("startup_data_ms=%.1f", (time.perf_counter() - started) * 1000)


class StartupLoader(QObject):
    early = pyqtSignal(object, bool)
    loaded = pyqtSignal(object, object)
    password_needed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, parent=None, prepare=None):
        super().__init__(parent)
        self.storage = StateStorage()
        self.prepare = prepare
        self._workers = set()
        self._closed = False

    def start(self, passphrase=""):
        if self._closed:
            return
        self.storage.passphrase = passphrase
        worker = StartupWorker(self.storage, self.prepare, self)
        self._workers.add(worker)
        worker.early.connect(self.early)
        worker.loaded.connect(self.loaded)
        worker.password_needed.connect(self.password_needed)
        worker.failed.connect(self.failed)
        worker.finished.connect(lambda: self._finished(worker))
        worker.start()

    def _finished(self, worker):
        self._workers.discard(worker)
        worker.deleteLater()

    def cancel(self):
        self._closed = True
        for worker in self._workers:
            worker.requestInterruption()

    def finish_shutdown(self):
        self.cancel()
        # Called after the GUI loop has exited: keep QThreads alive until completion.
        for worker in tuple(self._workers):
            worker.wait()


class MetadataWorker(QThread):
    ready = pyqtSignal(object)

    def __init__(self, xray_path, singbox_path, parent=None):
        super().__init__(parent)
        self.paths = (xray_path, singbox_path)

    def run(self):
        from ..engines.xray import get_xray_version
        from ..engines.singbox.core_updater import installed_version
        from ..engines.zapret.manager import ZapretManager
        result = {"xray": "", "singbox": "", "presets": []}
        for key, call in (
            ("xray", lambda: get_xray_version(self.paths[0]) or ""),
            ("singbox", lambda: installed_version(Path(self.paths[1])) or ""),
            ("presets", ZapretManager.list_preset_infos),
        ):
            if self.isInterruptionRequested():
                return
            try:
                result[key] = call()
            except Exception:
                pass
        self.ready.emit(result)
