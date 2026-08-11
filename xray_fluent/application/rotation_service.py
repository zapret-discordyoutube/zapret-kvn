"""Ротация выходных серверов по таймеру.

Пул нод целиком попадает в конфиг xray как несколько proxy-outbound'ов под общим
балансировщиком. Переключение делается командой ``xray api bo``, которая фиксирует
выбор балансировщика на нужном теге — ядро при этом не перезапускается и живые
соединения не рвутся (см. :mod:`xray_fluent.engines.xray.balancer_api`).

Модуль намеренно не зависит от Qt и от контроллера: он считает состав пула и
выбирает следующую ноду, а всю работу с процессами и таймерами делает вызывающий код.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import random

from ..link_parser import is_native_singbox_outbound
from ..models import AppSettings, Node


#: Тег балансировщика в конфиге xray.
BALANCER_TAG = "proxy-balancer"
#: Тег первого proxy-outbound; совпадает с одиночным режимом ради совместимости.
PRIMARY_OUTBOUND_TAG = "proxy"
#: Префикс, по которому балансировщик отбирает outbound'ы (совпадение по префиксу).
OUTBOUND_SELECTOR = "proxy"

ROTATION_MODES = ("random", "sequential")
ROTATION_POOLS = ("all", "group", "tag", "subscription")

MIN_INTERVAL_SEC = 30
MAX_INTERVAL_SEC = 24 * 60 * 60
MAX_POOL_NODES = 50
MIN_POOL_NODES = 2


@dataclass(slots=True)
class RotationPlan:
    """Состав пула ротации и раскладка тегов по нодам."""

    nodes: list[Node] = field(default_factory=list)
    #: node.id -> тег outbound'а в конфиге xray
    tags: dict[str, str] = field(default_factory=dict)
    #: сколько нод отобралось до усечения (для честного лога, см. AC6)
    candidates: int = 0

    @property
    def truncated(self) -> bool:
        return self.candidates > len(self.nodes)

    def tag_for(self, node_id: str | None) -> str:
        return self.tags.get(str(node_id or ""), PRIMARY_OUTBOUND_TAG)

    def contains(self, node_id: str | None) -> bool:
        return str(node_id or "") in self.tags

    def signature_payload(self) -> dict[str, object]:
        """Идентичность пула: меняется вместе с конфигом, но не при смене активной ноды."""

        return {"tags": [[self.tags[node.id], node.outbound] for node in self.nodes]}


def normalize_rotation_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in ROTATION_MODES else "random"


def normalize_rotation_pool(value: str) -> str:
    pool = str(value or "").strip().lower()
    return pool if pool in ROTATION_POOLS else "all"


def rotation_max_nodes(settings: AppSettings) -> int:
    return max(MIN_POOL_NODES, min(int(settings.rotation_max_nodes or 0) or MIN_POOL_NODES, MAX_POOL_NODES))


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


def is_rotatable_node(node: Node) -> bool:
    """Ротация живёт внутри xray, поэтому native sing-box outbound'ы в пул не берутся."""

    return bool(node.outbound) and not is_native_singbox_outbound(node)


def build_rotation_plan(
    settings: AppSettings,
    nodes: list[Node],
    selected_node_id: str | None = None,
) -> RotationPlan | None:
    """Собрать пул. ``None`` — ротация неприменима, работаем в одноузловом режиме."""

    if not settings.rotation_enabled:
        return None

    candidates = [
        node
        for node in nodes
        if is_rotatable_node(node) and node_matches_pool(node, settings)
        and not (settings.rotation_only_alive and node.is_alive is False)
    ]
    if len(candidates) < MIN_POOL_NODES:
        return None

    # Порядок (а значит и раскладка тегов) зависит ТОЛЬКО от состава пула.
    # Если бы тег `proxy` доставался активной ноде, то при каждом переключении
    # теги перетасовывались бы, а работающий xray сохранял бы старую раскладку —
    # и команда `bo proxy-N` уводила бы трафик на чужой сервер.
    candidates.sort(key=lambda node: (node.sort_order, node.id))
    limit = rotation_max_nodes(settings)
    selected = candidates[:limit]
    if selected_node_id and not any(node.id == str(selected_node_id) for node in selected):
        # Активная нода обязана быть в конфиге, даже если не прошла по лимиту.
        active = next((node for node in candidates if node.id == str(selected_node_id)), None)
        if active is not None:
            selected = [active, *selected[: limit - 1]]
            selected.sort(key=lambda node: (node.sort_order, node.id))

    tags = {
        node.id: (PRIMARY_OUTBOUND_TAG if index == 0 else f"{PRIMARY_OUTBOUND_TAG}-{index + 1}")
        for index, node in enumerate(selected)
    }
    return RotationPlan(nodes=selected, tags=tags, candidates=len(candidates))


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


def rotation_pool_signature(plan: RotationPlan | None) -> str:
    if plan is None:
        return ""
    return json.dumps(plan.signature_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
