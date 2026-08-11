from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from .link_parser import parse_single, validate_node_outbound
from .models import Node, SubscriptionInfo


MAX_SUBSCRIPTION_NODES = 10_000

_KNOWN_SCHEMES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "socks://",
    "socks5://",
    "http://",
    "https://",
)
_SKIPPED_XRAY_PROTOCOLS = {"freedom", "blackhole", "dns", "loopback"}
_SKIPPED_SINGBOX_TYPES = {
    "direct",
    "block",
    "dns",
    "selector",
    "urltest",
    "url-test",
    "logical",
}
_SUPPORTED_XRAY_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "hysteria",
    "wireguard",
}
_SUPPORTED_SINGBOX_TYPES = {
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
}
_COMMENT_HEADER_RE = re.compile(r"^\s*(?:#|//)\s*([^:]+?)\s*:\s*(.*?)\s*$")


class SubscriptionParseError(ValueError):
    pass


@dataclass(slots=True)
class SubscriptionMetadata:
    title: str = ""
    provider_interval_hours: int | None = None
    info: SubscriptionInfo = field(default_factory=SubscriptionInfo)
    moved_permanently_to: str = ""


@dataclass(slots=True)
class ParsedSubscription:
    nodes: list[Node]
    metadata: SubscriptionMetadata
    warnings: list[str] = field(default_factory=list)
    skipped: int = 0


def validate_filter_patterns(include_pattern: str, exclude_pattern: str) -> None:
    for label, pattern in (("include", include_pattern), ("exclude", exclude_pattern)):
        if not pattern:
            continue
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise SubscriptionParseError(f"Некорректный {label} regex: {exc}") from exc


def source_key_for_node(node: Node) -> str:
    outbound = _without_display_fields(node.outbound)
    canonical = json.dumps(outbound, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_subscription_payload(
    payload: bytes | str,
    *,
    headers: Mapping[str, Any] | None = None,
    source_url: str = "",
    include_pattern: str = "",
    exclude_pattern: str = "",
    hidden_source_keys: set[str] | None = None,
    max_nodes: int = MAX_SUBSCRIPTION_NODES,
) -> ParsedSubscription:
    validate_filter_patterns(include_pattern, exclude_pattern)
    text = _decode_utf8(payload).lstrip("\ufeff")
    decoded = _decode_whole_body_base64(text)
    if decoded is not None:
        text = decoded.lstrip("\ufeff")

    normalized_headers = _normalize_headers(headers or {})
    content_headers = _headers_from_content(text)
    for key, value in content_headers.items():
        normalized_headers.setdefault(key, value)

    metadata = _parse_metadata(normalized_headers, source_url)
    nodes, warnings, skipped = _parse_nodes(text, max_nodes=max_nodes)
    if not nodes:
        detail = warnings[0] if warnings else "поддерживаемые серверы не найдены"
        raise SubscriptionParseError(f"Подписка не содержит валидных серверов: {detail}")

    include_re = re.compile(include_pattern, re.IGNORECASE) if include_pattern else None
    exclude_re = re.compile(exclude_pattern, re.IGNORECASE) if exclude_pattern else None
    hidden = hidden_source_keys or set()
    filtered: list[Node] = []
    duplicate_records: set[str] = set()

    for node in nodes:
        provider_name = node.name or node.server or node.scheme
        node.provider_name = provider_name
        base_key = source_key_for_node(node)
        record_key = hashlib.sha256(
            f"{base_key}\0{provider_name}".encode("utf-8")
        ).hexdigest()
        if record_key in duplicate_records:
            skipped += 1
            continue
        duplicate_records.add(record_key)

        node.source_key = base_key
        if node.source_key in hidden or base_key in hidden:
            skipped += 1
            continue
        if include_re and include_re.search(provider_name) is None:
            skipped += 1
            continue
        if exclude_re and exclude_re.search(provider_name) is not None:
            skipped += 1
            continue
        filtered.append(node)
        if len(filtered) > max_nodes:
            raise SubscriptionParseError(f"Подписка содержит больше {max_nodes} серверов")

    if not filtered:
        raise SubscriptionParseError("После применения фильтров в подписке не осталось серверов")
    return ParsedSubscription(filtered, metadata, warnings, skipped)


def _decode_utf8(payload: bytes | str) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SubscriptionParseError("Ответ подписки не является UTF-8 текстом") from exc


def _decode_whole_body_base64(text: str) -> str | None:
    stripped = "".join(text.split())
    if not stripped or _looks_like_plain_payload(text):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", stripped):
        return None
    padded = stripped + "=" * ((4 - len(stripped) % 4) % 4)
    try:
        decoded_bytes = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        decoded = decoded_bytes.decode("utf-8-sig")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return decoded if _looks_like_plain_payload(decoded) else None


def _looks_like_plain_payload(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n \t")
    lowered = stripped.lower()
    return (
        lowered.startswith(_KNOWN_SCHEMES)
        or lowered.startswith("{")
        or lowered.startswith("[")
        or "[interface]" in lowered
        or any(f"\n{scheme}" in lowered for scheme in _KNOWN_SCHEMES)
    )


def _parse_nodes(text: str, *, max_nodes: int) -> tuple[list[Node], list[str], int]:
    stripped = text.strip()
    if _looks_like_wireguard(stripped):
        try:
            node = parse_single(stripped)
            problem = validate_node_outbound(node)
            if problem:
                raise SubscriptionParseError(problem)
            return [node], [], 0
        except Exception as exc:
            return [], [str(exc)], 1

    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            return _parse_json_nodes(payload, max_nodes=max_nodes)

    nodes: list[Node] = []
    warnings: list[str] = []
    skipped = 0
    for index, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            node = parse_single(line)
            problem = validate_node_outbound(node)
            if problem:
                raise SubscriptionParseError(problem)
        except Exception as exc:
            skipped += 1
            warnings.append(f"Строка {index}: {exc}")
            continue
        nodes.append(node)
        if len(nodes) > max_nodes:
            raise SubscriptionParseError(f"Подписка содержит больше {max_nodes} серверов")
    return nodes, warnings, skipped


def _parse_json_nodes(payload: Any, *, max_nodes: int) -> tuple[list[Node], list[str], int]:
    candidates: list[dict[str, Any]] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                candidates.extend(_json_candidates(item))
    elif isinstance(payload, dict):
        candidates.extend(_json_candidates(payload))
    else:
        return [], ["Корень JSON должен быть объектом или массивом"], 1

    nodes: list[Node] = []
    warnings: list[str] = []
    skipped = 0
    for index, candidate in enumerate(candidates, start=1):
        reason = _skip_json_candidate(candidate)
        if reason:
            skipped += 1
            if reason != "служебный outbound":
                warnings.append(f"JSON #{index}: {reason}")
            continue
        structural_problem = _validate_json_candidate(candidate)
        if structural_problem:
            skipped += 1
            warnings.append(f"JSON #{index}: {structural_problem}")
            continue
        try:
            raw = json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))
            node = parse_single(raw)
            problem = validate_node_outbound(node)
            if problem:
                raise SubscriptionParseError(problem)
            tag = str(candidate.get("tag") or "").strip()
            if tag:
                node.name = tag
            node.link = raw
            endpoint = _json_endpoint(candidate)
            if endpoint is not None:
                node.server, node.port = endpoint
        except Exception as exc:
            skipped += 1
            warnings.append(f"JSON #{index}: {exc}")
            continue
        nodes.append(node)
        if len(nodes) > max_nodes:
            raise SubscriptionParseError(f"Подписка содержит больше {max_nodes} серверов")
    return nodes, warnings, skipped


def _json_candidates(item: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    outbounds = item.get("outbounds")
    endpoints = item.get("endpoints")
    if isinstance(outbounds, list) or isinstance(endpoints, list):
        if isinstance(outbounds, list):
            result.extend(dict(value) for value in outbounds if isinstance(value, dict))
        if isinstance(endpoints, list):
            result.extend(dict(value) for value in endpoints if isinstance(value, dict))
        return result
    if "protocol" in item or "type" in item:
        return [dict(item)]
    return []


def _skip_json_candidate(candidate: dict[str, Any]) -> str:
    protocol = str(candidate.get("protocol") or "").strip().lower()
    native_type = str(candidate.get("type") or "").strip().lower()
    if protocol in _SKIPPED_XRAY_PROTOCOLS or native_type in _SKIPPED_SINGBOX_TYPES:
        return "служебный outbound"
    if candidate.get("detour"):
        return "зависимые sing-box outbounds с detour не импортируются"
    proxy_settings = candidate.get("proxySettings")
    if isinstance(proxy_settings, dict) and proxy_settings.get("tag"):
        return "зависимые Xray outbounds с proxySettings не импортируются"
    if not protocol and not native_type:
        return "нет protocol/type"
    if protocol and protocol not in _SUPPORTED_XRAY_PROTOCOLS:
        return f"неподдерживаемый Xray protocol: {protocol}"
    if native_type and native_type not in _SUPPORTED_SINGBOX_TYPES:
        return f"неподдерживаемый sing-box type: {native_type}"
    return ""


def _validate_json_candidate(candidate: dict[str, Any]) -> str:
    protocol = str(candidate.get("protocol") or "").strip().lower()
    native_type = str(candidate.get("type") or "").strip().lower()
    if native_type:
        if native_type == "wireguard":
            return ""
        server = str(candidate.get("server") or "").strip()
        has_port = bool(candidate.get("server_port") or candidate.get("server_ports"))
        if not server or not has_port:
            return f"{native_type} не содержит server/server_port"
        if native_type in {"vless", "vmess", "tuic"} and not str(
            candidate.get("uuid") or ""
        ).strip():
            return f"{native_type} не содержит uuid"
        if native_type in {"trojan", "hysteria2"} and not str(
            candidate.get("password") or ""
        ).strip():
            return f"{native_type} не содержит password"
        if native_type == "shadowsocks" and not (
            str(candidate.get("method") or "").strip()
            and str(candidate.get("password") or "").strip()
        ):
            return "shadowsocks не содержит method/password"
        return ""

    settings = candidate.get("settings")
    if not isinstance(settings, dict):
        return f"{protocol} не содержит settings"
    if protocol in {"vless", "vmess"}:
        entries = settings.get("vnext")
        entry = entries[0] if isinstance(entries, list) and entries and isinstance(entries[0], dict) else {}
        users = entry.get("users")
        user = users[0] if isinstance(users, list) and users and isinstance(users[0], dict) else {}
        if not str(entry.get("address") or "").strip() or not _valid_port(entry.get("port")):
            return f"{protocol} не содержит адрес или порт"
        if not str(user.get("id") or "").strip():
            return f"{protocol} не содержит id пользователя"
        return ""
    if protocol in {"trojan", "shadowsocks", "socks", "http"}:
        entries = settings.get("servers")
        entry = entries[0] if isinstance(entries, list) and entries and isinstance(entries[0], dict) else {}
        if not str(entry.get("address") or "").strip() or not _valid_port(entry.get("port")):
            return f"{protocol} не содержит адрес или порт"
        if protocol in {"trojan", "shadowsocks"} and not str(entry.get("password") or "").strip():
            return f"{protocol} не содержит password"
        if protocol == "shadowsocks" and not str(entry.get("method") or "").strip():
            return "shadowsocks не содержит method"
        return ""
    if protocol == "hysteria":
        if not str(settings.get("address") or "").strip() or not _valid_port(settings.get("port")):
            return "hysteria не содержит адрес или порт"
        try:
            version = int(settings.get("version") or 0)
        except (TypeError, ValueError):
            version = 0
        if version != 2:
            return "hysteria поддерживается только с version=2"
        return ""
    if protocol == "wireguard":
        peers = settings.get("peers")
        peer = peers[0] if isinstance(peers, list) and peers and isinstance(peers[0], dict) else {}
        if not str(settings.get("secretKey") or "").strip():
            return "wireguard не содержит secretKey"
        if not str(peer.get("publicKey") or "").strip():
            return "wireguard peer не содержит publicKey"
        if _split_endpoint(str(peer.get("endpoint") or "")) is None:
            return "wireguard peer не содержит корректный endpoint"
    return ""


def _json_endpoint(candidate: dict[str, Any]) -> tuple[str, int] | None:
    protocol = str(candidate.get("protocol") or "").strip().lower()
    if not protocol:
        return None
    settings = candidate.get("settings")
    if not isinstance(settings, dict):
        return None
    if protocol in {"vless", "vmess"}:
        entries = settings.get("vnext") or []
        entry = entries[0] if entries and isinstance(entries[0], dict) else {}
        return str(entry.get("address") or ""), int(entry.get("port") or 0)
    if protocol in {"trojan", "shadowsocks", "socks", "http"}:
        entries = settings.get("servers") or []
        entry = entries[0] if entries and isinstance(entries[0], dict) else {}
        return str(entry.get("address") or ""), int(entry.get("port") or 0)
    if protocol == "hysteria":
        return str(settings.get("address") or ""), int(settings.get("port") or 0)
    if protocol == "wireguard":
        peers = settings.get("peers") or []
        peer = peers[0] if peers and isinstance(peers[0], dict) else {}
        return _split_endpoint(str(peer.get("endpoint") or ""))
    return None


def _split_endpoint(value: str) -> tuple[str, int] | None:
    try:
        parsed = urlsplit(f"//{value.strip()}")
        port = parsed.port
    except ValueError:
        return None
    return (parsed.hostname, port) if parsed.hostname and port else None


def _valid_port(value: Any) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False


def _without_display_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _without_display_fields(item)
            for key, item in value.items()
            if str(key) not in {"tag", "remarks", "name"}
        }
    if isinstance(value, list):
        return [_without_display_fields(item) for item in value]
    return value


def _normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        text = str(value or "").strip()
        if text:
            result[str(key).strip().lower()] = text
    return result


def _headers_from_content(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in text.splitlines()[:10]:
        match = _COMMENT_HEADER_RE.match(line)
        if match:
            headers[match.group(1).strip().lower()] = match.group(2).strip()
    return headers


def _parse_metadata(headers: dict[str, str], source_url: str) -> SubscriptionMetadata:
    info = _parse_subscription_info(headers.get("subscription-userinfo", ""))
    info.web_page_url = _safe_http_url(headers.get("profile-web-page-url", ""))
    info.support_url = _safe_http_url(headers.get("support-url", ""))
    interval: int | None = None
    try:
        raw_interval = int(headers.get("profile-update-interval", "") or 0)
        interval = raw_interval if raw_interval > 0 else None
    except ValueError:
        interval = None
    return SubscriptionMetadata(
        title=_profile_title(headers, source_url),
        provider_interval_hours=interval,
        info=info,
        moved_permanently_to=_safe_http_url(headers.get("moved-permanently-to", "")),
    )


def _profile_title(headers: dict[str, str], source_url: str) -> str:
    title = unquote(headers.get("profile-title", "").strip())
    if title.lower().startswith("base64:"):
        try:
            encoded = title.split(":", 1)[1].strip()
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            title = base64.b64decode(
                encoded.replace("-", "+").replace("_", "/")
            ).decode("utf-8").strip()
        except (ValueError, binascii.Error, UnicodeDecodeError):
            title = ""
    if title:
        return title
    disposition = headers.get("content-disposition", "")
    match = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", disposition, re.IGNORECASE)
    if match:
        name = unquote(match.group(1)).strip().strip('"')
        name = re.sub(r"\.(?:txt|json|ya?ml)$", "", name, flags=re.IGNORECASE)
        if name:
            return name
    parsed = urlsplit(source_url)
    if parsed.fragment:
        return unquote(parsed.fragment).strip()
    basename = unquote(parsed.path.rstrip("/").rsplit("/", 1)[-1])
    basename = re.sub(r"\.(?:txt|json|ya?ml)$", "", basename, flags=re.IGNORECASE)
    return basename or (parsed.hostname or "Подписка")


def _parse_subscription_info(value: str) -> SubscriptionInfo:
    values: dict[str, int] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        try:
            values[key.strip().lower()] = max(0, int(raw.strip()))
        except ValueError:
            continue
    return SubscriptionInfo(
        upload=values.get("upload", 0),
        download=values.get("download", 0),
        total=values.get("total", values.get("totl", 0)),
        expire=values.get("expire", 0),
    )


def _safe_http_url(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text)
    return text if parsed.scheme.lower() in {"http", "https"} and parsed.hostname else ""


def _looks_like_wireguard(text: str) -> bool:
    return any(line.strip().lower() == "[interface]" for line in text.splitlines())
