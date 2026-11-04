"""Кнопка «Поддержка»: собрать архив, найти открытое имя сайта, открыть страницу."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from ..network.fetch_diagnosis import host_tag
from .bundle import SupportBundle, append_support_files
from .site import support_url

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SupportResult:
    zip_path: Path
    url: str
    bundle: SupportBundle


def prepare_support(
    zip_path: Path,
    log_dir: Path,
    *,
    url_resolver: Callable[[], str] = support_url,
) -> SupportResult:
    """Открытое имя сайта + журналы в архив. Ждёт сеть: только из фонового потока."""

    from urllib.parse import urlsplit

    url = url_resolver()
    host = urlsplit(url).hostname or ""
    bundle = append_support_files(zip_path, log_dir, mirror_tag=host_tag(host, 443) if host else "")
    _log.info("support: архив %s собран (журналы: %s), страница %s", zip_path.name, ", ".join(bundle.included) or "нет", host_tag(host, 443))
    return SupportResult(Path(zip_path), url, bundle)


class _SupportWorker(QThread):
    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, zip_path: Path, log_dir: Path, url_resolver, parent=None) -> None:
        super().__init__(parent)
        self._zip_path = zip_path
        self._log_dir = log_dir
        self._url_resolver = url_resolver

    def run(self) -> None:
        try:
            self.done.emit(prepare_support(self._zip_path, self._log_dir, url_resolver=self._url_resolver))
        except Exception as error:  # noqa: BLE001 — отчёт об отказе, а не падение потока
            _log.exception("support: не удалось подготовить обращение")
            self.failed.emit(f"{type(error).__name__}: {error}")


class SupportAction(QObject):
    """Одно нажатие кнопки. Все внешние действия переданы снаружи — их можно подменить."""

    started = pyqtSignal()
    finished_ok = pyqtSignal(object)   # SupportResult
    failed = pyqtSignal(str)

    def __init__(
        self,
        build_zip: Callable[[], Path],
        log_dir: Path,
        *,
        open_url: Callable[[str], object],
        reveal_file: Callable[[Path], object],
        url_resolver: Callable[[], str] = support_url,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._build_zip = build_zip
        self._log_dir = Path(log_dir)
        self._open_url = open_url
        self._reveal_file = reveal_file
        self._url_resolver = url_resolver
        self._worker: _SupportWorker | None = None

    @property
    def running(self) -> bool:
        return self._worker is not None

    def start(self) -> bool:
        if self._worker is not None:
            return False
        try:
            zip_path = self._build_zip()
        except Exception as error:  # noqa: BLE001
            _log.exception("support: архив журналов не собран")
            self.failed.emit(f"Не удалось собрать архив: {error}")
            return False
        worker = _SupportWorker(Path(zip_path), self._log_dir, self._url_resolver, self)
        worker.done.connect(self._on_done)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(self._on_thread_finished)
        self._worker = worker
        self.started.emit()
        worker.start()
        return True

    def _on_done(self, result: SupportResult) -> None:
        # Сначала файл, потом страница: человек видит, что прикладывать, когда сайт откроется.
        try:
            self._reveal_file(result.zip_path)
        except Exception:  # noqa: BLE001 — проводник не обязателен
            _log.exception("support: проводник не открылся")
        self._open_url(result.url)
        self.finished_ok.emit(result)

    def _on_failed(self, message: str) -> None:
        self.failed.emit(message)

    def _on_thread_finished(self) -> None:
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.deleteLater()


__all__ = ["SupportAction", "SupportResult", "prepare_support"]
