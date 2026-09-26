"""«Умная проверка»: уход с медленного сервера только после контрольного замера.

Простой порог скорости переключал исправный сервер сразу после окончания
загрузки: простой ≠ медленно (1d489aa).  Здесь решение принимается в три шага:

1. Пассивное подозрение само ничего не переключает.  Подозрение — это
   СПРОС при низкой скорости: не меньше ``SMART_SWITCH_SUSPICION_SEC`` подряд
   есть хотя бы одно проксируемое соединение, счётчики байт которого растут
   (пауза роста не дольше ``SMART_SWITCH_DEMAND_GAP_SEC``), а загрузка через
   туннель ниже ``SMART_SWITCH_THRESHOLD_BPS``.  Данные о соединениях считает
   ``LiveMetricsWorker`` (``diagnostics/proxy_demand.py``).  Нет спроса — нет
   подозрения.
2. Контрольный замер текущего сервера — короткая ограниченная загрузка через
   работающий локальный прокси (``ActiveProxySpeedProbeWorker``, вне GUI-потока).
   Скорость не ниже порога — ложная тревога, пауза ``SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC``.
3. Сервер подтверждённо медленный — до ``SMART_SWITCH_MAX_CANDIDATES`` кандидатов
   меряются штатным ``SpeedTestWorker`` (временный xray на своих портах, активное
   подключение не трогается).  Переключение — только если лучший кандидат не
   ниже порога и быстрее текущего в ``SMART_SWITCH_BETTER_FACTOR`` раз, и только
   через ``set_selected_node(..., reset_auto_switch=False)``.

Анти-дребезг: после переключения ``SMART_SWITCH_POST_SWITCH_HOLD_SEC`` без
умных переключений, покинутый сервер помечается медленным на
``SMART_SWITCH_SLOW_MARK_SEC`` (не кандидат), не больше
``SMART_SWITCH_MAX_PER_HOUR`` переключений в час.  Ничего не делается во время
переходов, теста скорости и пакетного пинга, при выключенном авто-переключении
(главный переключатель) или выключенной настройке «Переключать при низкой
скорости», а также при ручном удержании сервера.

Все сетевые замеры — в QThread-воркерах; на GUI-поток приходят только их
сигналы (связь с методами контроллера — очередь Qt).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable

from ..constants import ROUTING_GLOBAL, SPEED_TEST_DEFAULT_URL, XRAY_PATH_DEFAULT
from .auto_switch_service import _transition_in_progress

if TYPE_CHECKING:
    from .controller import AppController
    from ..profiles.models import Node


# Порог «медленно»: 1 Мбит/с ≈ 128 КБ/с.  Ниже — видео уже буферизуется, веб
# ощутимо тормозит; выше — сервер пригоден, переключение дороже выигрыша.
SMART_SWITCH_THRESHOLD_BPS = 128 * 1024
# Сколько секунд подряд нужно спрос + низкая скорость, чтобы заподозрить сервер.
SMART_SWITCH_SUSPICION_SEC = 20.0
# Спрос живой, пока счётчики проксируемых соединений росли не раньше этого срока:
# keep-alive раз в 15–30 с спросом не считается.
SMART_SWITCH_DEMAND_GAP_SEC = 5.0
# Данные о соединениях старше этого срока считаются отсутствующими.
SMART_SWITCH_DEMAND_MAX_AGE_SEC = 6.0
# Ложная тревога / кандидата лучше нет — столько не перепроверять.
SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC = 5 * 60.0
# После умного переключения — столько без новых умных переключений.
SMART_SWITCH_POST_SWITCH_HOLD_SEC = 10 * 60.0
# Покинутый медленный сервер не кандидат столько времени.
SMART_SWITCH_SLOW_MARK_SEC = 30 * 60.0
SMART_SWITCH_MAX_PER_HOUR = 3
SMART_SWITCH_MAX_CANDIDATES = 3
# Кандидат должен быть быстрее текущего сервера хотя бы во столько раз.
SMART_SWITCH_BETTER_FACTOR = 2.0
# Контрольный замер: не больше 3 МБ и не дольше 6 с (и текущий, и кандидаты).
SMART_SWITCH_PROBE_MAX_BYTES = 3 * 1024 * 1024
SMART_SWITCH_PROBE_TIMEOUT_SEC = 6.0
# Один и тот же не-российский файл для всех замеров: сравнение «как с
# одинаковым», а российский адрес шаблоны маршрутизируют напрямую (замер
# показал бы скорость провайдера, а не сервера).  Не DoH и не IP-discovery.
SMART_SWITCH_PROBE_URL = SPEED_TEST_DEFAULT_URL
# Свои временные порты для xray кандидатов: не пересекаются с ручным тестом
# скорости (19100/19101).
SMART_SWITCH_TEMP_SOCKS_PORT = 19102
SMART_SWITCH_TEMP_HTTP_PORT = 19103
# Страховка: проверка (замер текущего + до 3 кандидатов) укладывается в ~30 с;
# если сигнал воркера так и не пришёл, через этот срок состояние сбрасывается.
SMART_SWITCH_CHECK_DEADLINE_SEC = 120.0

_HOUR_SEC = 3600.0
_MIB = 1024 * 1024

PHASE_IDLE = "idle"
PHASE_PROBE_CURRENT = "probe_current"
PHASE_PROBE_CANDIDATES = "probe_candidates"


@dataclass
class SmartSwitchState:
    """Состояние умной проверки на время жизни контроллера."""

    # Пассивное наблюдение.
    low_since: float = 0.0
    observed_node_id: str | None = None
    demand_seen_at: float = 0.0
    demand_active: int = 0
    demand_down_bps: float = 0.0
    last_growth_at: float = 0.0
    # Активная проверка.
    phase: str = PHASE_IDLE
    phase_started_at: float = 0.0
    generation: int = 0
    node_id: str | None = None
    current_bps: float = 0.0
    candidate_ids: list[str] = field(default_factory=list)
    results: dict[str, float | None] = field(default_factory=dict)
    probe_worker: Any = None
    candidate_worker: Any = None
    workers: list[Any] = field(default_factory=list)
    # Анти-дребезг.
    cooldown_until: float = 0.0
    hold_until: float = 0.0
    slow_until: dict[str, float] = field(default_factory=dict)
    switch_times: list[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Чистая политика (без Qt и I/O)
# ---------------------------------------------------------------------------


def observe(
    state: SmartSwitchState,
    now: float,
    down_bps: float,
    traffic_valid: bool,
    demand: dict[str, Any] | None,
) -> bool:
    """Учесть очередной отсчёт метрик; True — подозрение созрело."""

    if isinstance(demand, dict):
        state.demand_seen_at = now
        try:
            state.demand_active = int(demand.get("active") or 0)
            state.demand_down_bps = float(demand.get("down_bps") or 0.0)
            growing = int(demand.get("growing") or 0)
        except (TypeError, ValueError):
            state.demand_active, state.demand_down_bps, growing = 0, 0.0, 0
        if growing > 0:
            state.last_growth_at = now

    fresh = state.demand_seen_at > 0 and now - state.demand_seen_at <= SMART_SWITCH_DEMAND_MAX_AGE_SEC
    has_demand = (
        fresh
        and state.demand_active > 0
        and state.last_growth_at > 0
        and now - state.last_growth_at <= SMART_SWITCH_DEMAND_GAP_SEC
    )
    # Скорость — по проксируемым соединениям; общий счётчик ядра (включая
    # закрытые короткие соединения) тоже снимает подозрение, если он высок.
    fast = (
        state.demand_down_bps >= SMART_SWITCH_THRESHOLD_BPS
        or float(down_bps or 0.0) >= SMART_SWITCH_THRESHOLD_BPS
    )
    if not traffic_valid or not has_demand or fast:
        state.low_since = 0.0
        return False
    if state.low_since == 0.0:
        state.low_since = now
        return False
    return now - state.low_since >= SMART_SWITCH_SUSPICION_SEC


def switches_last_hour(state: SmartSwitchState, now: float) -> int:
    state.switch_times = [ts for ts in state.switch_times if now - ts < _HOUR_SEC]
    return len(state.switch_times)


def is_slow_marked(state: SmartSwitchState, node_id: str, now: float) -> bool:
    until = state.slow_until.get(node_id)
    if until is None:
        return False
    if now >= until:
        state.slow_until.pop(node_id, None)
        return False
    return True


def select_candidates(
    nodes: Iterable[Node],
    current_id: str | None,
    state: SmartSwitchState,
    now: float,
    available_ids: set[str] | None = None,
    limit: int = SMART_SWITCH_MAX_CANDIDATES,
) -> list[Node]:
    """Лучшие по недавней скорости/пингу кандидаты, которых можно замерить.

    Пропускаются: текущий, мёртвые (is_alive=False), помеченные медленными,
    техработы и ноды, которые штатный тест скорости не умеет мерить (native
    sing-box).  Если ядро держит пул горячего переключения, берутся ноды из
    него — переключение без перезапуска; пул пуст по кандидатам — все.
    """

    from ..engines.hysteria.runtime_contract import node_is_maintenance
    from ..network.speed_test_worker import should_skip_speed_test

    eligible: list[Node] = []
    for node in nodes:
        if node.id == current_id or node.is_alive is False:
            continue
        if is_slow_marked(state, node.id, now):
            continue
        if node_is_maintenance(node) or should_skip_speed_test(node)[0]:
            continue
        eligible.append(node)
    if available_ids:
        pooled = [node for node in eligible if node.id in available_ids]
        if pooled:
            eligible = pooled

    def _rank(node: Node) -> tuple:
        speed = node.speed_mbps if node.speed_mbps and node.speed_mbps > 0 else None
        ping = node.ping_ms if node.ping_ms is not None else float("inf")
        return (speed is None, -(speed or 0.0), ping, node.sort_order)

    return sorted(eligible, key=_rank)[: max(0, int(limit))]


def decide(current_bps: float, results: dict[str, float | None]) -> tuple[str, float] | None:
    """Лучший кандидат, если он не ниже порога и в 2 раза быстрее текущего."""

    measured = [(node_id, bps) for node_id, bps in results.items() if bps is not None and bps > 0]
    if not measured:
        return None
    node_id, bps = max(measured, key=lambda item: item[1])
    if bps < SMART_SWITCH_THRESHOLD_BPS:
        return None
    if bps < SMART_SWITCH_BETTER_FACTOR * max(0.0, float(current_bps)):
        return None
    return node_id, bps


def _kbps(bps: float | None) -> str:
    return "—" if bps is None else f"{bps / 1024:.0f} KB/s"


# ---------------------------------------------------------------------------
# Связка с контроллером
# ---------------------------------------------------------------------------


def smart_state(controller: AppController) -> SmartSwitchState:
    state = getattr(controller, "_smart_switch", None)
    if state is None:
        state = SmartSwitchState()
        controller._smart_switch = state
    return state


def _worker_running(worker: Any) -> bool:
    if worker is None:
        return False
    is_running = getattr(worker, "isRunning", None)
    return bool(is_running()) if callable(is_running) else True


def gate_reason(controller: AppController, now: float) -> str | None:
    """Почему умная проверка сейчас недопустима (None — можно)."""

    settings = controller.state.settings
    if not settings.auto_switch_enabled:
        return "авто-переключение выключено"
    if not getattr(settings, "auto_switch_low_speed_enabled", True):
        return "переключение при низкой скорости выключено"
    if not controller.connected or controller._switching or controller._reconnecting:
        return "нет устойчивого подключения"
    if _transition_in_progress(controller):
        return "идёт переход подключения"
    if getattr(controller, "_auto_switch_manual_hold", False):
        return "сервер выбран вручную"
    if len(controller.state.nodes) < 2:
        return "нет других серверов"
    if now < float(getattr(controller, "_auto_switch_warmup_until", 0.0) or 0.0):
        return "прогрев после смены сервера"
    if _worker_running(getattr(controller, "_speed_worker", None)):
        return "идёт тест скорости"
    if _worker_running(getattr(controller, "_ping_worker", None)):
        return "идёт пинг серверов"
    return None


def check_smart_switch(
    controller: AppController,
    down_bps: float,
    *,
    traffic_valid: bool = True,
    demand: dict[str, Any] | None = None,
    now: float | None = None,
) -> None:
    """Отсчёт метрик из GUI-потока: копить подозрение и запускать проверку."""

    state = smart_state(controller)
    now = time.monotonic() if now is None else now
    if state.phase != PHASE_IDLE:
        if now - state.phase_started_at < SMART_SWITCH_CHECK_DEADLINE_SEC:
            return
        cancel_smart_check(controller, "замер не завершился вовремя")
        state.cooldown_until = now + SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC
        return
    if gate_reason(controller, now) is not None:
        state.low_since = 0.0
        return
    if now < state.cooldown_until or now < state.hold_until:
        state.low_since = 0.0
        return
    if switches_last_hour(state, now) >= SMART_SWITCH_MAX_PER_HOUR:
        state.low_since = 0.0
        return
    current_id = controller.state.selected_node_id
    if state.observed_node_id != current_id:
        state.observed_node_id = current_id
        state.low_since = 0.0
    if not observe(state, now, down_bps, traffic_valid, demand):
        return
    _start_current_probe(controller, state, now)


def _start_current_probe(controller: AppController, state: SmartSwitchState, now: float) -> None:
    node = controller.selected_node
    if node is None:
        state.low_since = 0.0
        return
    duration = now - state.low_since
    state.low_since = 0.0
    controller._log(
        f"[auto-switch] подозрение: {node.name} — {_kbps(state.demand_down_bps)} при "
        f"активной загрузке ({state.demand_active} соедин.) {duration:.0f} с; контрольный замер"
    )
    session = getattr(controller, "_active_session", None)
    http_port = int(getattr(session, "http_port", 0) or 0) if session is not None else 0
    tun_mode = bool(getattr(session, "tun_mode", False)) if session is not None else False
    if http_port <= 0 and not tun_mode:
        controller._log("[auto-switch] замер невозможен: нет локального HTTP-прокси — проверка отложена")
        state.cooldown_until = now + SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC
        return
    state.generation += 1
    state.phase = PHASE_PROBE_CURRENT
    state.phase_started_at = now
    state.node_id = node.id
    state.current_bps = 0.0
    state.results = {}
    state.candidate_ids = []
    worker = create_probe_worker(http_port if http_port > 0 else None)
    state.probe_worker = worker
    _track_worker(state, worker)
    worker.measured.connect(controller._on_smart_probe_measured)
    worker.start()


def _abort_reason(controller: AppController, state: SmartSwitchState, now: float) -> str | None:
    reason = gate_reason(controller, now)
    if reason is not None:
        return reason
    if controller.state.selected_node_id != state.node_id:
        return "сервер сменился во время проверки"
    return None


def _finish(state: SmartSwitchState, now: float, *, cooldown: bool) -> None:
    state.phase = PHASE_IDLE
    state.probe_worker = None
    state.candidate_worker = None
    state.low_since = 0.0
    if cooldown:
        state.cooldown_until = now + SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC


def on_current_probe_measured(
    controller: AppController,
    worker: Any,
    bps: float | None,
    *,
    now: float | None = None,
) -> None:
    state = smart_state(controller)
    if worker is None or worker is not state.probe_worker or state.phase != PHASE_PROBE_CURRENT:
        return
    now = time.monotonic() if now is None else now
    state.probe_worker = None
    reason = _abort_reason(controller, state, now)
    if reason is not None:
        controller._log(f"[auto-switch] проверка прервана: {reason}")
        _finish(state, now, cooldown=False)
        return
    node = controller.selected_node
    name = node.name if node is not None else str(state.node_id)
    if bps is not None and bps >= SMART_SWITCH_THRESHOLD_BPS:
        controller._log(
            f"[auto-switch] замер {name}: {_kbps(bps)} ≥ порога {_kbps(SMART_SWITCH_THRESHOLD_BPS)} — "
            f"ложная тревога, повтор не раньше чем через {SMART_SWITCH_FALSE_ALARM_COOLDOWN_SEC / 60:.0f} мин"
        )
        _finish(state, now, cooldown=True)
        return
    # Замер не удался совсем (ни байта за отведённое время) — сервер не отдаёт
    # данные, считаем скорость нулевой; решение всё равно за замером кандидатов.
    state.current_bps = float(bps or 0.0)
    controller._log(
        f"[auto-switch] замер {name}: {_kbps(bps) if bps is not None else 'данные не пришли'} — "
        f"сервер подтверждённо медленный"
    )
    candidates = select_candidates(
        controller.state.nodes,
        state.node_id,
        state,
        now,
        available_ids=_available_ids(controller),
    )
    if not candidates:
        controller._log("[auto-switch] кандидатов для замера нет — остаёмся на текущем сервере")
        _finish(state, now, cooldown=True)
        return
    controller._log(
        "[auto-switch] кандидаты: " + ", ".join(candidate.name for candidate in candidates)
    )
    state.phase = PHASE_PROBE_CANDIDATES
    state.candidate_ids = [candidate.id for candidate in candidates]
    state.results = {}
    candidate_worker = create_candidate_worker(controller, candidates)
    state.candidate_worker = candidate_worker
    _track_worker(state, candidate_worker)
    candidate_worker.result.connect(controller._on_smart_candidate_result)
    candidate_worker.completed.connect(controller._on_smart_candidates_done)
    candidate_worker.start()


def on_candidate_result(
    controller: AppController,
    worker: Any,
    node_id: str,
    speed_mbps: float | None,
    _is_alive: bool = False,
) -> None:
    state = smart_state(controller)
    if worker is None or worker is not state.candidate_worker:
        return
    if node_id not in state.candidate_ids:
        return
    state.results[node_id] = float(speed_mbps) * _MIB if speed_mbps else None


def on_candidates_done(controller: AppController, worker: Any, *, now: float | None = None) -> None:
    state = smart_state(controller)
    if worker is None or worker is not state.candidate_worker or state.phase != PHASE_PROBE_CANDIDATES:
        return
    now = time.monotonic() if now is None else now
    state.candidate_worker = None
    reason = _abort_reason(controller, state, now)
    if reason is not None:
        controller._log(f"[auto-switch] проверка прервана: {reason}")
        _finish(state, now, cooldown=False)
        return
    names = {node.id: node.name for node in controller.state.nodes}
    controller._log(
        "[auto-switch] замер кандидатов: "
        + ", ".join(f"{names.get(node_id, node_id)} {_kbps(state.results.get(node_id))}" for node_id in state.candidate_ids)
    )
    choice = decide(state.current_bps, state.results)
    if choice is None:
        controller._log(
            f"[auto-switch] решение: остаёмся — нет кандидата ≥ {_kbps(SMART_SWITCH_THRESHOLD_BPS)} "
            f"и в {SMART_SWITCH_BETTER_FACTOR:g} раза быстрее текущего ({_kbps(state.current_bps)})"
        )
        _finish(state, now, cooldown=True)
        return
    if switches_last_hour(state, now) >= SMART_SWITCH_MAX_PER_HOUR:
        controller._log("[auto-switch] решение: остаёмся — исчерпан лимит переключений в час")
        _finish(state, now, cooldown=True)
        return
    target_id, target_bps = choice
    old_id = state.node_id or ""
    old_name = names.get(old_id, old_id)
    target_name = names.get(target_id, target_id)
    state.slow_until[old_id] = now + SMART_SWITCH_SLOW_MARK_SEC
    state.hold_until = now + SMART_SWITCH_POST_SWITCH_HOLD_SEC
    state.switch_times.append(now)
    _finish(state, now, cooldown=False)
    # Общий анти-дребезг с детектором мёртвого сервера; счётчик цикла
    # «перебраны все серверы» относится только к отказам и не трогается.
    controller._auto_switch_last_switch = now
    controller._log(
        f"[auto-switch] решение: переключение {old_name} ({_kbps(state.current_bps)}) → "
        f"{target_name} ({_kbps(target_bps)})"
    )
    controller.status.emit(
        "warning",
        f"Сервер {old_name} медленный ({_kbps(state.current_bps)}) — "
        f"переключено на {target_name} ({_kbps(target_bps)})",
    )
    # Единственный путь смены ноды (hot-switch-invariants): горячий свитч с
    # честным откатом в очередь переходов; анти-дребезг не сбрасывается.
    controller.set_selected_node(target_id, reset_auto_switch=False)


def cancel_smart_check(controller: AppController, reason: str) -> None:
    """Прервать проверку без ожидания потоков (отключение, тест скорости…)."""

    state = getattr(controller, "_smart_switch", None)
    if state is None:
        return
    state.low_since = 0.0
    if state.phase == PHASE_IDLE:
        return
    for worker in (state.probe_worker, state.candidate_worker):
        cancel = getattr(worker, "cancel", None)
        if callable(cancel):
            cancel()
    state.generation += 1
    state.phase = PHASE_IDLE
    state.probe_worker = None
    state.candidate_worker = None
    controller._log(f"[auto-switch] проверка скорости отменена: {reason}")


def shutdown_smart_check(controller: AppController, wait_ms: int = 8000) -> None:
    """Выход из приложения: отменить и дождаться воркеров (блокирующий путь)."""

    state = getattr(controller, "_smart_switch", None)
    if state is None:
        return
    for worker in list(state.workers):
        cancel = getattr(worker, "cancel", None)
        if callable(cancel):
            cancel()
    for worker in list(state.workers):
        if _worker_running(worker):
            worker.wait(wait_ms)
    state.phase = PHASE_IDLE
    state.probe_worker = None
    state.candidate_worker = None


def _track_worker(state: SmartSwitchState, worker: Any) -> None:
    """Держать сильную ссылку на QThread до его finished."""

    state.workers.append(worker)
    finished = getattr(worker, "finished", None)
    if finished is None:
        return

    def _release(_done: list[bool] = []) -> None:
        if _done:
            return
        _done.append(True)
        try:
            state.workers.remove(worker)
        except ValueError:
            pass
        delete_later = getattr(worker, "deleteLater", None)
        if callable(delete_later):
            delete_later()

    finished.connect(_release)


def _available_ids(controller: AppController) -> set[str] | None:
    getter = getattr(controller, "_rotation_available_ids", None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:
        return None


def create_probe_worker(http_port: int | None):
    from ..network.speed_test_worker import ActiveProxySpeedProbeWorker

    return ActiveProxySpeedProbeWorker(
        http_port,
        SMART_SWITCH_PROBE_URL,
        timeout=SMART_SWITCH_PROBE_TIMEOUT_SEC,
        max_bytes=SMART_SWITCH_PROBE_MAX_BYTES,
    )


def create_candidate_worker(controller: AppController, nodes: list[Node]):
    from ..network.speed_test_worker import SpeedTestWorker
    from ..profiles.models import RoutingSettings
    from ..profiles.path_utils import resolve_configured_path

    resolved = resolve_configured_path(
        controller.state.settings.xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    xray_path = str(resolved) if resolved else controller.state.settings.xray_path
    # Временный xray кандидата пускает весь трафик замера через кандидата:
    # иначе правила «напрямую» дали бы скорость провайдера и ложную победу.
    routing = RoutingSettings()
    routing.mode = ROUTING_GLOBAL
    return SpeedTestWorker(
        nodes,
        xray_path=xray_path,
        routing=routing,
        timeout=SMART_SWITCH_PROBE_TIMEOUT_SEC,
        rounds=1,
        max_bytes=SMART_SWITCH_PROBE_MAX_BYTES,
        url=SMART_SWITCH_PROBE_URL,
        socks_port=SMART_SWITCH_TEMP_SOCKS_PORT,
        http_port=SMART_SWITCH_TEMP_HTTP_PORT,
    )
