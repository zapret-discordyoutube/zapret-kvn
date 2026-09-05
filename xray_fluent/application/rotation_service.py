"""Ротация выходных серверов по таймеру.

Собственного транспорта у ротации нет: все пригодные ноды и так загружены в ядро
как пул outbound'ов (:mod:`xray_fluent.application.outbound_pool_service`), а
переключение делает штатный горячий свитч — он фиксирует выбор по тегу, который
ядро получило при запуске. Здесь остаётся только политика: какие ноды участвуют,
какая идёт следующей и через сколько.

Модуль намеренно не зависит от Qt и от контроллера, поэтому проверяется напрямую.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random

from ..profiles.models import AppSettings, Node


ROTATION_MODES = ("random", "sequential")
ROTATION_POOLS = ("all", "group", "tag", "subscription")

MIN_INTERVAL_SEC = 30
MAX_INTERVAL_SEC = 24 * 60 * 60
MAX_POOL_NODES = 50
MIN_POOL_NODES = 2


@dataclass(slots=True)
class RotationPlan:
    """Ноды, между которыми крутится ротация."""

    nodes: list[Node] = field(default_factory=list)
    #: сколько нод подошло до усечения (для честного лога, см. AC6)
    candidates: int = 0

    @property
    def truncated(self) -> bool:
        return self.candidates > len(self.nodes)

    def contains(self, node_id: str | None) -> bool:
        target = str(node_id or "")
        return any(node.id == target for node in self.nodes)

    def node_ids(self) -> list[str]:
        return [node.id for node in self.nodes]


def normalize_rotation_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in ROTATION_MODES else "random"


def normalize_rotation_pool(value: str) -> str:
    pool = str(value or "").strip().lower()
    return pool if pool in ROTATION_POOLS else "all"


def rotation_max_nodes(settings: AppSettings) -> int:
    requested = int(settings.rotation_max_nodes or 0) or MIN_POOL_NODES
    return max(MIN_POOL_NODES, min(requested, MAX_POOL_NODES))


def node_matches_pool(node: Node, settings: AppSettings) -> bool:
    pool = normalize_rotation_pool(settings.rotation_pool)
    value = str(settings.rotation_pool_value or "").strip()
    if pool == "all" or not value:
        return pool == "all"
    if pool == "group":
        return node.group == value
    if pool == "tag":
        return value in node.tags
    return str(node.subscription_id or "") == value


def build_rotation_plan(
    settings: AppSettings,
    nodes: list[Node],
    selected_node_id: str | None = None,
    *,
    available_ids: set[str] | None = None,
) -> RotationPlan | None:
    """Собрать пул. ``None`` — ротация неприменима, работаем в одноузловом режиме.

    ``available_ids`` — ноды, которые ядро реально держит в своём пуле. Ротация не
    имеет права предложить ноду, которой в запущенном ядре нет: переключение на неё
    молча не сработало бы.
    """

    if not settings.rotation_enabled:
        return None

    candidates = [
        node
        for node in nodes
        if node_matches_pool(node, settings)
        and (available_ids is None or node.id in available_ids)
        and not (settings.rotation_only_alive and node.is_alive is False)
    ]
    if len(candidates) < MIN_POOL_NODES:
        return None

    candidates.sort(key=lambda node: (node.sort_order, node.id))
    limit = rotation_max_nodes(settings)
    selected = candidates[:limit]
    if selected_node_id and not any(node.id == str(selected_node_id) for node in selected):
        # Активная нода обязана оставаться в ротации, даже если не прошла по лимиту,
        # иначе после первого же тика вернуться на неё будет нельзя.
        active = next((node for node in candidates if node.id == str(selected_node_id)), None)
        if active is not None:
            selected = sorted(
                [active, *selected[: limit - 1]], key=lambda node: (node.sort_order, node.id)
            )
    return RotationPlan(nodes=selected, candidates=len(candidates))


def pick_next_node(
    plan: RotationPlan,
    current_node_id: str | None,
    mode: str,
    rng: random.Random | None = None,
) -> Node | None:
    """Следующая нода пула. ``random`` не повторяет текущую, ``sequential`` идёт по кругу."""

    if not plan.nodes:
        return None
    if len(plan.nodes) == 1:
        return plan.nodes[0]

    current = str(current_node_id or "")
    if normalize_rotation_mode(mode) == "sequential":
        index = next((i for i, node in enumerate(plan.nodes) if node.id == current), -1)
        return plan.nodes[(index + 1) % len(plan.nodes)]

    generator = rng or random.Random()
    others = [node for node in plan.nodes if node.id != current]
    return generator.choice(others or plan.nodes)


def rotation_interval_ms(settings: AppSettings, rng: random.Random | None = None) -> int:
    """Интервал до следующего переключения с учётом разброса."""

    base = max(MIN_INTERVAL_SEC, min(int(settings.rotation_interval_sec or 0), MAX_INTERVAL_SEC))
    jitter = max(0, min(int(settings.rotation_jitter_pct or 0), 90))
    if jitter:
        generator = rng or random.Random()
        spread = base * jitter / 100.0
        base = max(MIN_INTERVAL_SEC, base + generator.uniform(-spread, spread))
    return int(base * 1000)
