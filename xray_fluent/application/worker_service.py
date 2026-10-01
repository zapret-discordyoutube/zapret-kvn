from __future__ import annotations

from datetime import datetime, timezone
import random
from typing import TYPE_CHECKING

from ..network.connectivity_test import ConnectivityTestWorker
from ..constants import (
    DEFAULT_HTTP_PORT,
    SPEED_TEST_MAX_BYTES,
    SPEED_TEST_PAUSE_RANGE_SEC,
    SPEED_TEST_RETRIES,
    SPEED_TEST_SETTLE_MAX_SEC,
    SPEED_TEST_WARMUP_SEC,
    SPEED_TEST_WINDOW_SEC,
    XRAY_PATH_DEFAULT,
)
from ..profiles.path_utils import resolve_configured_path
from ..network.ping_worker import apply_ping_measurement
from ..network.speed_test_worker import SpeedTestWorker
from .smart_switch_service import cancel_smart_check
from .worker_keeper import start_kept

if TYPE_CHECKING:
    from .controller import AppController
    from ..network.ping_service import PingOutcome
    from ..profiles.models import Node


def ping_nodes(controller: AppController, node_ids: set[str] | None = None) -> None:
    """Поставить серверы в очередь пинга; уже измеряемые не повторяются.

    Ничего не отменяет и не ждёт: новые серверы вливаются в текущий раунд.
    """
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if nodes:
        controller.ping.request(nodes)


def cancel_ping(controller: AppController) -> bool:
    """Снять с очереди ещё не начатые замеры пинга."""
    return controller.ping.cancel() > 0


def speed_test_nodes(controller: AppController, node_ids: set[str] | None = None) -> bool:
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if not nodes:
        return False

    if controller._speed_worker and controller._speed_worker.isRunning():
        controller.status.emit("info", "Тест скорости уже выполняется. Остановите его перед новым запуском.")
        return False
    # Ручной тест важнее фоновой проверки авто-переключения: её замеры
    # конкурировали бы за канал (порты у них разные, ждать не нужно).
    cancel_smart_check(controller, "запущен тест скорости")

    resolved = resolve_configured_path(
        controller.state.settings.xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    xray_path = str(resolved) if resolved else controller.state.settings.xray_path

    # Случайный порядок: перебор серверов всегда в порядке списка — лишний
    # повторяемый признак для наблюдателя на линии.
    nodes = list(nodes)
    random.shuffle(nodes)

    controller._speed_total = len(nodes)
    controller._speed_completed = 0
    controller._speed_skipped = []
    controller.bulk_task_progress.emit("speed", 0, controller._speed_total, False)
    controller._speed_worker = SpeedTestWorker(
        nodes,
        xray_path=xray_path,
        max_bytes=SPEED_TEST_MAX_BYTES,
        retries=SPEED_TEST_RETRIES,
        warmup=SPEED_TEST_WARMUP_SEC,
        window=SPEED_TEST_WINDOW_SEC,
        settle_max=SPEED_TEST_SETTLE_MAX_SEC,
        partial_on_error=True,
        pause_range=SPEED_TEST_PAUSE_RANGE_SEC,
    )
    controller._speed_worker.result.connect(controller._on_speed_result)
    # Пропуски копятся и показываются одной строкой в конце: по сообщению на
    # сервер давало десятки всплывающих плашек на списке native-нод.
    skipped = controller._speed_skipped
    controller._speed_worker.skipped.connect(
        lambda _node_id, message: skipped.append(message)
    )
    controller._speed_worker.progress.connect(controller._on_speed_progress)
    controller._speed_worker.node_progress.connect(controller._on_speed_node_progress)
    controller._speed_worker.completed.connect(controller._on_speed_complete)
    start_kept(controller._background_workers, controller._speed_worker)
    return True


def cancel_speed_test(controller: AppController) -> bool:
    worker = controller._speed_worker
    if worker is None or not worker.isRunning():
        controller.status.emit("info", "Тест скорости сейчас не выполняется")
        return False
    worker.cancel()
    controller.status.emit("info", "Останавливаю тест скорости...")
    return True


def test_connectivity(controller: AppController, url: str | None = None) -> None:
    target = (url or "https://www.gstatic.com/generate_204").strip()
    if not target:
        target = "https://www.gstatic.com/generate_204"

    if controller._connectivity_worker and controller._connectivity_worker.isRunning():
        controller.status.emit("info", "Тест подключения уже выполняется")
        return

    http_port = controller.get_effective_http_proxy_port() or DEFAULT_HTTP_PORT
    controller._connectivity_worker = ConnectivityTestWorker(http_port, target, tun_mode=controller.state.settings.tun_mode)
    controller._connectivity_worker.result.connect(controller._on_connectivity_result)
    start_kept(controller._background_workers, controller._connectivity_worker)


def on_ping_measured(controller: AppController, outcome: PingOutcome) -> None:
    target = outcome.target
    node = controller._get_node_by_id(target.node_id)
    if node is None:
        return
    if not target.matches(node):
        # Адрес сервера сменили, пока шёл замер: чужой результат не пишем,
        # но строка должна выйти из состояния «измеряется».
        controller.ping_updated.emit(node.id, node.ping_ms)
        return
    if outcome.peers:
        from .node_runtime_service import remember_country_addresses

        remember_country_addresses(controller, node, outcome.peers, refresh=False)
        controller._country_ping_pending = True
    apply_ping_measurement(node, outcome.ping_ms)
    ts = datetime.now(timezone.utc).isoformat()
    node.ping_history.append((ts, node.ping_ms))
    if len(node.ping_history) > 50:
        node.ping_history = node.ping_history[-50:]
    controller.ping_updated.emit(node.id, node.ping_ms)


def on_ping_progress(controller: AppController, done: int, total: int, finished: bool) -> None:
    controller.bulk_task_progress.emit("ping", done, total, finished)
    if not finished:
        return
    if getattr(controller, "_country_ping_pending", False):
        controller._country_ping_pending = False
        controller._start_country_ip_resolution()
    controller.schedule_save()


def on_speed_result(controller: AppController, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    node = controller._get_node_by_id(node_id)
    if node is not None:
        node.speed_mbps = speed_mbps
        if is_alive or node.is_alive is None:
            node.is_alive = is_alive
        ts = datetime.now(timezone.utc).isoformat()
        node.speed_history.append((ts, speed_mbps))
        if len(node.speed_history) > 50:
            node.speed_history = node.speed_history[-50:]
    controller.speed_updated.emit(node_id, speed_mbps, is_alive)


def on_speed_progress(controller: AppController, current: int, total: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller._speed_completed = current
    controller.bulk_task_progress.emit("speed", current, total, False)


def on_speed_node_progress(controller: AppController, node_id: str, percent: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller.speed_progress_updated.emit(node_id, max(0, min(100, int(percent))))


def on_speed_complete(controller: AppController) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    worker = controller._speed_worker
    cancelled = bool(worker.was_cancelled) if worker is not None else False
    completed = worker.completed_nodes if worker is not None else controller._speed_completed
    controller._speed_completed = completed
    if cancelled:
        controller.speed_test_cancelled.emit(completed, controller._speed_total)
    controller.bulk_task_progress.emit("speed", completed, controller._speed_total, True)
    controller._speed_worker = None
    controller.save()
    skipped = list(getattr(controller, "_speed_skipped", None) or ())
    controller._speed_skipped = []
    if len(skipped) == 1:
        controller.status.emit("info", skipped[0])
    elif skipped:
        controller.status.emit(
            "info",
            f"Тест скорости пропустил серверов: {len(skipped)} — их протоколы пока не измеряются.",
        )
    if cancelled:
        controller.status.emit("info", f"Тест скорости остановлен ({completed}/{controller._speed_total})")
    else:
        controller.status.emit("success", "Тест скорости завершён")


def on_connectivity_result(controller: AppController, ok: bool, message: str, elapsed_ms: int | None) -> None:
    if controller.sender() is not controller._connectivity_worker:
        return
    controller._connectivity_worker = None
    if ok and elapsed_ms is not None:
        text = f"Подключение в порядке: {elapsed_ms} мс"
        controller.status.emit("success", text)
        controller._log(f"[test] {message} ({elapsed_ms} ms)")
    else:
        controller.status.emit("warning", "Тест подключения не пройден")
        controller._log(f"[test] {message}")
    controller.connectivity_test_done.emit(ok, message, elapsed_ms)
