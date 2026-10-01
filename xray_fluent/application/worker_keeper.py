"""Время жизни короткоживущих ``QThread``-воркеров.

Правило одно: сильную ссылку на поток отпускает только его собственный
``QThread.finished`` — он испускается после выхода из ``run()``. Слот любого
своего сигнала воркера (``completed``, ``result``, ``done``…) вызывается,
пока ``run()`` ещё не вернулся: если там обнулить последнюю ссылку, Python
удалит работающий поток, и Qt завершит процесс
(``QThread: Destroyed while thread is still running``).

Поля контроллера вроде ``_speed_worker`` остаются «текущей задачей» для
проверок занятости и фильтра ``sender()``; жизнь потока держит корзина.
"""

from __future__ import annotations

from typing import Any


def keep_until_finished(bucket: list, worker: Any) -> None:
    """Держать ``worker`` в ``bucket`` до его ``finished``, затем ``deleteLater``."""

    if any(item is worker for item in bucket):
        return
    bucket.append(worker)
    finished = getattr(worker, "finished", None)
    if finished is None:
        return

    def _release(_done: list[bool] = []) -> None:
        if _done:
            return
        _done.append(True)
        # finished испускается из хвоста QThreadPrivate::finish, когда поток
        # формально ещё «running»; этот хвост — микросекунды, дождаться его.
        is_running = getattr(worker, "isRunning", None)
        if callable(is_running) and is_running():
            worker.wait()
        for index, item in enumerate(bucket):
            if item is worker:
                del bucket[index]
                break
        delete_later = getattr(worker, "deleteLater", None)
        if callable(delete_later):
            delete_later()

    finished.connect(_release)


def start_kept(bucket: list, worker: Any) -> Any:
    """Взять воркер под охрану и запустить его."""

    keep_until_finished(bucket, worker)
    worker.start()
    return worker


def wait_all(bucket: list, timeout_ms: int) -> None:
    """Выход из приложения: дождаться оставшихся потоков (блокирующий путь)."""

    for worker in list(bucket):
        is_running = getattr(worker, "isRunning", None)
        if callable(is_running) and is_running():
            worker.wait(timeout_ms)
