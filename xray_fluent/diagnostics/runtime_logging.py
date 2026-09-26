from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import logging
import re
from threading import Lock
from typing import Any, Iterable, Mapping


_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SHARE_URI_RE = re.compile(
    r"(?i)\b(?:hy2|hysteria2|hysteria|vless|vmess|trojan|ss)://\S+"
)
_SECRET_PAIR_RE = re.compile(
    r"(?i)((?:[\"']?)(?:auth|password|passwd|obfs[-_]?password|pinsha256|pin_sha256|"
    r"clientkey|client_key|privatekey|private_key|publickey|public_key|shortid|"
    r"uuid|presharedkey|pre_shared_key|header[_-]?protection[_-]?key|certificate_sha256|token|ech)(?:[\"']?)"
    r"\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_OUTBOUND_RE = re.compile(r"outbound/[^\[]+\[([^\]]+)\]")
_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")


def strip_terminal_controls(text: str) -> str:
    """Keep structured log fields intact while removing terminal decoration."""
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", str(text or "")))


def node_ref(node_id: str) -> str:
    """Короткая необратимая метка узла: хэш случайного id, а не адреса."""

    node_id = str(node_id or "")
    return hashlib.sha256(node_id.encode("utf-8")).hexdigest()[:12] if node_id else "unknown"


# Адрес внутри имени вида 185-109-21-120.sslip.io / 185.109.21.120.nip.io:
# такое имя раскрывает IP сервера, и ядро потом печатает сам IP.
_EMBEDDED_IPV4_RE = re.compile(r"(?<![0-9])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})(?![0-9])")
# Граница имени/IPv4: «1.2.3.4» не совпадает внутри «11.2.3.45», а
# «a.example.com» — внутри «b.a.example.com»; «:порт» и точка в конце
# предложения границу не нарушают.
_NAME_LEFT = r"(?<![0-9A-Za-z.-])"
_NAME_RIGHT = r"(?![0-9A-Za-z-]|\.[0-9A-Za-z])"
_IPV6_LEFT = r"(?<![0-9A-Fa-f:])"
_IPV6_RIGHT = r"(?![0-9A-Fa-f:])"


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True  # доменное имя
    return not (
        address.is_loopback or address.is_private or address.is_link_local
        or address.is_unspecified or address.is_multicast or address.is_reserved
    )


def _address_variants(address: str) -> set[str]:
    host = str(address or "").strip().strip("[]").rstrip(".").casefold()
    if len(host) < 4 or host == "localhost" or not _is_public_address(host):
        return set()
    variants = {host}
    try:
        variants.add(str(ipaddress.ip_address(host)))
    except ValueError:
        for match in _EMBEDDED_IPV4_RE.finditer(host):
            octets = match.groups()
            if all(int(octet) <= 255 for octet in octets):
                embedded = ".".join(str(int(octet)) for octet in octets)
                if _is_public_address(embedded):
                    variants.add(embedded)
    return variants


def _trie_regex(words: Iterable[str]) -> str:
    """Альтернация с общими префиксами: сотни адресов пула без перебора каждого."""

    trie: dict = {}
    for word in words:
        node = trie
        for char in word:
            node = node.setdefault(char, {})
        node[""] = {}

    def build(node: dict) -> str:
        terminal = "" in node
        branches = [re.escape(char) + build(child) for char, child in sorted(node.items()) if char]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        # Жадно: сначала самое длинное совпадение, короткое — только как запасной вариант.
        return f"(?:{body})?" if terminal else body

    return build(trie)


class _ServerAddressRegistry:
    """Адреса серверов, которые нельзя выпускать в лог и экспорт.

    Реестр только растёт за сессию: в буфере логов остаются строки про
    удалённые узлы. Снимок (шаблон, словарь) меняется атомарно — строки
    маскируются из потоков чтения ядер без блокировки.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._refs: dict[str, str] = {}
        self._snapshot: tuple[re.Pattern[str] | None, dict[str, str]] = (None, {})

    def register(self, pairs: Iterable[tuple[str, str]]) -> None:
        with self._lock:
            changed = False
            for address, ref in pairs:
                for variant in _address_variants(address):
                    if variant not in self._refs:
                        self._refs[variant] = ref
                        changed = True
            if changed:
                self._rebuild()

    def ref_for(self, address: str) -> str:
        host = str(address or "").strip().strip("[]").rstrip(".").casefold()
        return self._snapshot[1].get(host, "")

    def _rebuild(self) -> None:
        names = [item for item in self._refs if ":" not in item]
        ipv6 = [item for item in self._refs if ":" in item]
        parts = []
        if names:
            parts.append(f"{_NAME_LEFT}{_trie_regex(names)}{_NAME_RIGHT}")
        if ipv6:
            parts.append(f"{_IPV6_LEFT}{_trie_regex(ipv6)}{_IPV6_RIGHT}")
        pattern = re.compile("|".join(parts), re.IGNORECASE) if parts else None
        self._snapshot = (pattern, dict(self._refs))

    def redact(self, text: str) -> str:
        pattern, refs = self._snapshot
        if pattern is None or not text:
            return text
        return pattern.sub(lambda match: f"<сервер {refs.get(match.group(0).casefold(), 'unknown')}>", text)

    def clear(self) -> None:
        with self._lock:
            self._refs.clear()
            self._snapshot = (None, {})


_SERVER_ADDRESSES = _ServerAddressRegistry()


def register_server_nodes(nodes: Iterable[Any]) -> None:
    """Запомнить адреса узлов: в логах они заменяются на ``<сервер node_ref>``."""

    _SERVER_ADDRESSES.register(
        (str(getattr(node, "server", "") or ""), node_ref(str(getattr(node, "id", "") or "")))
        for node in nodes or ()
    )


def register_server_aliases(server: str, addresses: Iterable[str]) -> None:
    """IP, в которые приложение само разрешило имя уже известного сервера."""

    ref = _SERVER_ADDRESSES.ref_for(server)
    if ref:
        _SERVER_ADDRESSES.register((str(address), ref) for address in addresses)


def redact_server_addresses(text: str) -> str:
    return _SERVER_ADDRESSES.redact(str(text or ""))


class ServerAddressLogFilter(logging.Filter):
    """Файловый лог: адреса серверов маскируются и в записях модулей."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact_server_addresses(message)
        if redacted != message:
            record.msg, record.args = redacted, ()
        return True


def redact_runtime_log(text: str, *, secrets: Iterable[str] = ()) -> str:
    """Remove transport credentials and server addresses, keeping the error reason."""

    clean = strip_terminal_controls(text)
    clean = _SHARE_URI_RE.sub("<ссылка скрыта>", clean)
    clean = _SECRET_PAIR_RE.sub(lambda match: f"{match.group(1)}<скрыто>", clean)
    clean = _UUID_RE.sub("<скрыто>", clean)
    for secret in secrets:
        value = str(secret or "")
        if len(value) >= 4:
            clean = clean.replace(value, "<скрыто>")
    return redact_server_addresses(clean).strip()


def _safe_field(value: Any, *, fallback: str = "", limit: int = 160) -> str:
    clean = redact_runtime_log(str(value or ""))
    clean = " ".join(clean.split())[:limit]
    return clean or fallback


@dataclass(frozen=True, slots=True)
class RuntimeNodeIdentity:
    """Кто этот узел — без адреса: адрес сервера в логи не попадает."""

    ref: str
    name: str
    protocol: str

    @classmethod
    def from_node(cls, node: Any) -> "RuntimeNodeIdentity":
        return cls(
            ref=node_ref(str(getattr(node, "id", "") or "")),
            name=_safe_field(getattr(node, "name", ""), fallback="без имени"),
            protocol=_safe_field(getattr(node, "scheme", ""), fallback="unknown", limit=40),
        )

    def fields(self) -> str:
        return (
            f"node={json.dumps(self.name, ensure_ascii=False)} "
            f"node_ref={self.ref} protocol={self.protocol}"
        )


@dataclass(slots=True)
class RuntimeLogContext:
    engine: str
    role: str
    mode: str
    generation: int
    selected: RuntimeNodeIdentity | None = None
    outbound_nodes: dict[str, RuntimeNodeIdentity] = field(default_factory=dict)


def contextualize_runtime_log(
    line: str,
    *,
    context: RuntimeLogContext,
    error: bool = False,
) -> str:
    clean = redact_runtime_log(line)
    marker = f"[{context.engine}]"
    error_marker = f"[{context.engine}-error]"
    if clean.startswith(marker) or clean.startswith(error_marker):
        return clean

    tag = ""
    match = _OUTBOUND_RE.search(clean)
    if match is not None:
        tag = match.group(1)
    identity = context.outbound_nodes.get(tag)
    if identity is None and (not tag or tag == "proxy"):
        identity = context.selected

    fields = [
        f"engine={context.engine}",
        f"role={context.role}",
        f"mode={context.mode}",
        f"generation={context.generation}",
    ]
    if tag:
        fields.append(f"outbound={tag}")
    if tag in {"direct", "block"}:
        fields.append("route=builtin")
    elif identity is not None:
        fields.append(identity.fields())
    prefix = error_marker if error else marker
    return f"{prefix}[{' '.join(fields)}] {clean}".strip()


def runtime_mapping_lines(context: RuntimeLogContext) -> list[str]:
    result: list[str] = []
    seen: set[tuple[str, RuntimeNodeIdentity]] = set()
    for tag, identity in sorted(context.outbound_nodes.items()):
        item = (tag, identity)
        if item in seen:
            continue
        seen.add(item)
        result.append(
            f"[runtime-map] engine={context.engine} role={context.role} "
            f"mode={context.mode} generation={context.generation} "
            f"outbound={tag} {identity.fields()}"
        )
    return result


def identities_for_tags(
    tags: Mapping[str, str] | None,
    nodes_by_id: Mapping[str, Any],
) -> dict[str, RuntimeNodeIdentity]:
    result: dict[str, RuntimeNodeIdentity] = {}
    for node_id, tag in (tags or {}).items():
        node = nodes_by_id.get(node_id)
        if node is None or not tag:
            continue
        identity = RuntimeNodeIdentity.from_node(node)
        result[str(tag)] = identity
        # Provider logs normally use the qualified tag, but retaining the leaf
        # makes diagnostics robust across core log-format changes.
        result.setdefault(str(tag).rsplit("/", 1)[-1], identity)
    return result
