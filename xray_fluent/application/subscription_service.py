from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from copy import deepcopy
import json
from urllib.parse import urlsplit

from ..models import AppState, Node, Subscription, SubscriptionUpdateResult, utc_now_iso
from ..subscription_http import SubscriptionFetchResult, sanitize_fetch_error
from ..subscription_parser import ParsedSubscription


@dataclass(slots=True)
class ReconcileOutcome:
    result: SubscriptionUpdateResult
    selected_node_changed: bool = False
    selected_node_removed: bool = False


def subscription_due(subscription: Subscription, now: datetime | None = None) -> bool:
    if not subscription.auto_update:
        return False
    now = now or datetime.now(timezone.utc)
    backoff = _parse_time(subscription.backoff_until)
    if backoff is not None and backoff > now:
        return False
    last_success = _parse_time(subscription.last_success_at)
    if last_success is None:
        return True
    return last_success + timedelta(hours=subscription.effective_interval_hours) <= now


def mark_subscription_failure(subscription: Subscription, message: str) -> SubscriptionUpdateResult:
    now = datetime.now(timezone.utc)
    subscription.last_checked_at = now.isoformat()
    subscription.failure_count += 1
    delay_minutes = 15 if subscription.failure_count == 1 else 60 if subscription.failure_count == 2 else 360
    subscription.backoff_until = (now + timedelta(minutes=delay_minutes)).isoformat()
    subscription.last_error = sanitize_fetch_error(RuntimeError(message))
    return SubscriptionUpdateResult(
        subscription_id=subscription.id,
        success=False,
        message=subscription.last_error,
    )


def apply_not_modified(
    subscription: Subscription,
    fetch: SubscriptionFetchResult,
) -> SubscriptionUpdateResult:
    now = utc_now_iso()
    subscription.last_checked_at = now
    subscription.last_success_at = now
    subscription.failure_count = 0
    subscription.backoff_until = None
    subscription.last_error = ""
    _apply_cache_headers(subscription, fetch)
    return SubscriptionUpdateResult(
        subscription_id=subscription.id,
        success=True,
        message="Подписка не изменилась",
        not_modified=True,
    )


def reconcile_subscription(
    state: AppState,
    subscription: Subscription,
    parsed: ParsedSubscription,
    fetch: SubscriptionFetchResult,
) -> ReconcileOutcome:
    if not subscription.name:
        subscription.name = parsed.metadata.title or "Подписка"
    old_nodes = [node for node in state.nodes if node.subscription_id == subscription.id]
    other_nodes = [node for node in state.nodes if node.subscription_id != subscription.id]
    old_by_key: dict[str, list[Node]] = {}
    for node in old_nodes:
        old_by_key.setdefault(node.source_key, []).append(node)

    old_by_fallback: dict[tuple[str, str, int, str], list[Node]] = {}
    for node in old_nodes:
        old_by_fallback.setdefault(_fallback_key(node), []).append(node)

    used_ids: set[str] = set()
    max_order = max((node.sort_order for node in state.nodes), default=0)
    selected_id = state.selected_node_id
    selected_before = next((node for node in old_nodes if node.id == selected_id), None)
    selected_changed = False
    added = 0
    updated = 0
    reconciled: list[Node] = []

    for incoming in parsed.nodes:
        incoming.subscription_id = subscription.id
        source_candidates = [
            node for node in old_by_key.get(incoming.source_key, []) if node.id not in used_ids
        ]
        match = next(
            (
                node
                for node in source_candidates
                if (node.provider_name or node.name).casefold()
                == (incoming.provider_name or incoming.name).casefold()
            ),
            None,
        )
        if match is None:
            match = _take_unused(source_candidates, used_ids)
        if match is None:
            fallback_matches = [
                node for node in old_by_fallback.get(_fallback_key(incoming), []) if node.id not in used_ids
            ]
            if len(fallback_matches) == 1:
                match = fallback_matches[0]
        if match is None:
            max_order += 1
            incoming.sort_order = max_order
            incoming.group = subscription.name or "Default"
            incoming.provider_name = incoming.provider_name or incoming.name
            reconciled.append(incoming)
            added += 1
            continue

        used_ids.add(match.id)
        old_outbound = _canonical_outbound(match)
        provider_name_before = match.provider_name or match.name
        local_name = match.name
        incoming.id = match.id
        incoming.name = incoming.provider_name if local_name in {"", provider_name_before} else local_name
        incoming.group = match.group
        incoming.tags = list(match.tags)
        incoming.ping_ms = match.ping_ms
        incoming.last_used_at = match.last_used_at
        incoming.created_at = match.created_at
        incoming.country_code = match.country_code
        incoming.speed_mbps = match.speed_mbps
        incoming.is_alive = match.is_alive
        incoming.ping_history = list(match.ping_history)
        incoming.speed_history = list(match.speed_history)
        incoming.sort_order = match.sort_order
        if match.id == selected_id and old_outbound != _canonical_outbound(incoming):
            selected_changed = True
        reconciled.append(incoming)
        updated += 1

    removed_nodes = [node for node in old_nodes if node.id not in used_ids]
    selected_removed = selected_before is not None and selected_before.id in {node.id for node in removed_nodes}
    if selected_removed:
        if reconciled:
            state.selected_node_id = reconciled[0].id
        elif other_nodes:
            state.selected_node_id = other_nodes[0].id
        else:
            state.selected_node_id = None

    _apply_success_metadata(subscription, parsed, fetch)
    state.nodes = other_nodes + reconciled
    result = SubscriptionUpdateResult(
        subscription_id=subscription.id,
        success=True,
        message=f"Серверов: {len(reconciled)}",
        added=added,
        updated=updated,
        removed=len(removed_nodes),
        skipped=parsed.skipped,
        warnings=list(parsed.warnings),
        reconnect_required=selected_changed or selected_removed,
    )
    return ReconcileOutcome(result, selected_changed, selected_removed)


def remove_subscription(state: AppState, subscription_id: str, *, keep_nodes: bool) -> bool:
    subscription = next((item for item in state.subscriptions if item.id == subscription_id), None)
    if subscription is None:
        return False
    owned = [node for node in state.nodes if node.subscription_id == subscription_id]
    selected_owned = any(node.id == state.selected_node_id for node in owned)
    if keep_nodes:
        for node in owned:
            node.subscription_id = None
            node.source_key = ""
            node.provider_name = node.name
    else:
        state.nodes = [node for node in state.nodes if node.subscription_id != subscription_id]
    state.subscriptions = [item for item in state.subscriptions if item.id != subscription_id]
    if selected_owned and not keep_nodes:
        state.selected_node_id = state.nodes[0].id if state.nodes else None
    return True


def hide_subscription_node(state: AppState, node_id: str) -> str | None:
    node = next((item for item in state.nodes if item.id == node_id), None)
    if node is None or not node.subscription_id or not node.source_key:
        return None
    subscription = next((item for item in state.subscriptions if item.id == node.subscription_id), None)
    if subscription is None:
        return None
    if node.source_key not in subscription.hidden_source_keys:
        subscription.hidden_source_keys.append(node.source_key)
    removed_ids = {
        item.id
        for item in state.nodes
        if item.subscription_id == subscription.id and item.source_key == node.source_key
    }
    state.nodes = [item for item in state.nodes if item.id not in removed_ids]
    if state.selected_node_id in removed_ids:
        same = [item for item in state.nodes if item.subscription_id == subscription.id]
        state.selected_node_id = (same[0].id if same else state.nodes[0].id if state.nodes else None)
    return subscription.id


def _apply_success_metadata(
    subscription: Subscription,
    parsed: ParsedSubscription,
    fetch: SubscriptionFetchResult,
) -> None:
    now = utc_now_iso()
    subscription.last_checked_at = now
    subscription.last_success_at = now
    subscription.failure_count = 0
    subscription.backoff_until = None
    subscription.last_error = ""
    metadata = parsed.metadata
    if not subscription.name:
        subscription.name = metadata.title
    subscription.provider_interval_hours = metadata.provider_interval_hours
    subscription.info = deepcopy(metadata.info)
    moved_url = metadata.moved_permanently_to
    url_was_replaced = False
    if moved_url:
        current_host = (urlsplit(subscription.url).hostname or "").lower()
        moved_host = (urlsplit(moved_url).hostname or "").lower()
        if current_host and current_host == moved_host:
            subscription.url = moved_url
            subscription.pending_url = ""
            url_was_replaced = True
        elif moved_host:
            subscription.pending_url = moved_url
    if url_was_replaced:
        subscription.etag = ""
        subscription.last_modified = ""
    else:
        _apply_cache_headers(subscription, fetch)


def _apply_cache_headers(subscription: Subscription, fetch: SubscriptionFetchResult) -> None:
    subscription.etag = fetch.headers.get("etag", subscription.etag)
    subscription.last_modified = fetch.headers.get("last-modified", subscription.last_modified)


def _take_unused(candidates: list[Node], used_ids: set[str]) -> Node | None:
    for node in candidates:
        if node.id not in used_ids:
            return node
    return None


def _fallback_key(node: Node) -> tuple[str, str, int, str]:
    return (
        node.scheme.lower(),
        node.server.lower(),
        int(node.port),
        (node.provider_name or node.name).casefold(),
    )


def _canonical_outbound(node: Node) -> str:
    return json.dumps(node.outbound, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
