from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import parse_qsl, quote, urlsplit


_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "t"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "f"})


def build_uri_client_config(
    raw_uri: str,
    outbound: dict[str, Any],
    *,
    relay_host: str,
    relay_port: int,
    relay_username: str,
    relay_password: str,
) -> dict[str, Any]:
    """Build an ephemeral official-client config without changing saved URI state.

    The application historically accepted a few Clash/sing-box aliases which
    the official Hysteria URI parser intentionally does not understand.  Keep
    the original URI as the source of truth, then express those already parsed
    semantics through official full-config fields for this process only.
    """

    pairs = tuple(parse_qsl(urlsplit(raw_uri).query, keep_blank_values=True))
    server_uri = _append_official_query_aliases(raw_uri, pairs)
    server_uri = _runtime_server_uri(server_uri, outbound, pairs)
    config: dict[str, Any] = {
        "server": server_uri,
        "lazy": True,
        "quic": {"disableChromeParrot": False},
        "socks5": {
            "listen": f"{relay_host}:{relay_port}",
            "username": relay_username,
            "password": relay_password,
            "disableUDP": False,
        },
    }

    tls_outbound = outbound.get("tls")
    tls_source = tls_outbound if isinstance(tls_outbound, dict) else {}
    tls: dict[str, Any] = {}
    sni = _query_value(pairs, "sni", "peer") or str(tls_source.get("server_name") or "")
    if sni:
        tls["sni"] = sni

    insecure_text = _query_value(
        pairs,
        "insecure",
        "skip-cert-verify",
        "skip_cert_verify",
        "allow_insecure",
        "allowInsecure",
    )
    insecure = _parse_bool(insecure_text)
    if insecure is not None:
        tls["insecure"] = insecure
    elif tls_source.get("insecure"):
        tls["insecure"] = True

    pin = _query_value(pairs, "pinSHA256", "pin_sha256", "pinsha256")
    if pin:
        tls["pinSHA256"] = pin
    ech = _query_value(pairs, "ech")
    if ech:
        tls["ech"] = ech
    if tls:
        config["tls"] = tls

    obfs_type = _query_value(pairs, "obfs").strip().lower()
    if obfs_type:
        obfs: dict[str, Any] = {"type": obfs_type}
        if obfs_type in {"salamander", "gecko"}:
            password = _query_value(pairs, "obfs-password", "obfs_password")
            obfs[obfs_type] = {"password": password}
        config["obfs"] = obfs

    hop_interval = _query_value(pairs, "hopInterval", "hop_interval")
    if hop_interval:
        config["transport"] = {
            "type": "udp",
            "udp": {"hopInterval": hop_interval},
        }

    bandwidth: dict[str, str] = {}
    for source_key, target_key in (("up_mbps", "up"), ("down_mbps", "down")):
        value = outbound.get(source_key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        bandwidth[target_key] = f"{max(0, int(value))} mbps"
    if bandwidth:
        config["bandwidth"] = bandwidth
    return config


def _append_official_query_aliases(
    raw_uri: str,
    pairs: Iterable[tuple[str, str]],
) -> str:
    items = tuple(pairs)
    additions: list[tuple[str, str]] = []
    mappings = (
        ("sni", ("peer",)),
        ("insecure", ("skip-cert-verify", "skip_cert_verify", "allow_insecure", "allowInsecure")),
        ("obfs", ()),
        ("obfs-password", ("obfs_password",)),
        ("pinSHA256", ("pin_sha256", "pinsha256")),
        ("ech", ()),
    )
    for canonical, aliases in mappings:
        if any(key == canonical for key, _value in items):
            continue
        value = _query_value(items, canonical, *aliases)
        if not value:
            continue
        if canonical == "insecure":
            parsed = _parse_bool(value)
            if parsed is not None:
                value = "true" if parsed else "false"
        additions.append((canonical, value))
    if not additions:
        return raw_uri

    parsed_uri = urlsplit(raw_uri)
    suffix = "&".join(f"{key}={quote(value, safe='')}" for key, value in additions)
    query = f"{parsed_uri.query}&{suffix}" if parsed_uri.query else suffix
    return parsed_uri._replace(query=query).geturl()


def _query_value(
    pairs: Iterable[tuple[str, str]],
    canonical: str,
    *aliases: str,
) -> str:
    items = tuple(pairs)
    empty_value: str | None = None
    for key, value in items:
        if key == canonical:
            if value:
                return value
            empty_value = value
    canonical_folded = canonical.casefold()
    for key, value in items:
        if key.casefold() == canonical_folded:
            if value:
                return value
            if empty_value is None:
                empty_value = value
    for alias in aliases:
        for key, value in items:
            if key == alias:
                if value:
                    return value
                if empty_value is None:
                    empty_value = value
        alias_folded = alias.casefold()
        for key, value in items:
            if key.casefold() == alias_folded:
                if value:
                    return value
                if empty_value is None:
                    empty_value = value
    return empty_value or ""


def _parse_bool(value: str) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return None


def _runtime_server_uri(
    raw_uri: str,
    outbound: dict[str, Any],
    pairs: Iterable[tuple[str, str]],
) -> str:
    # Query-based mport/ports is a legacy alias.  The official URI grammar
    # expects the port union in the authority, so rewrite only the ephemeral
    # process value while leaving Node.link and its fingerprint untouched.
    if not _query_value(pairs, "mport", "ports"):
        return raw_uri

    server_ports = outbound.get("server_ports")
    if isinstance(server_ports, (list, tuple)) and server_ports:
        ports = [str(item).replace(":", "-") for item in server_ports]
    else:
        port = int(outbound.get("server_port") or 0)
        if port <= 0:
            return raw_uri
        ports = [str(port)]

    parsed = urlsplit(raw_uri)
    host = str(parsed.hostname or "")
    if not host:
        return raw_uri
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    netloc = f"{userinfo}{host}:{','.join(ports)}"
    return parsed._replace(netloc=netloc).geturl()
