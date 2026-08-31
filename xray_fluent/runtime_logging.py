from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Iterable, Mapping


_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SHARE_URI_RE = re.compile(
    r"(?i)\b(?:hy2|hysteria2|hysteria|vless|vmess|trojan|ss)://\S+"
)
_SECRET_PAIR_RE = re.compile(
    r"(?i)((?:[\"']?)(?:auth|password|passwd|obfs[-_]?password|pinsha256|pin_sha256|"
    r"clientkey|client_key|privatekey|private_key|presharedkey|token|ech)(?:[\"']?)"
    r"\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
_OUTBOUND_RE = re.compile(r"outbound/[^\[]+\[([^\]]+)\]")


def redact_runtime_log(text: str, *, secrets: Iterable[str] = ()) -> str:
    """Remove transport credentials while keeping the useful error reason."""

    clean = _ANSI_RE.sub("", str(text or ""))
    clean = _CONTROL_RE.sub("", clean)
    clean = _SHARE_URI_RE.sub("<ссылка скрыта>", clean)
    clean = _SECRET_PAIR_RE.sub(lambda match: f"{match.group(1)}<скрыто>", clean)
    for secret in secrets:
        value = str(secret or "")
        if len(value) >= 4:
            clean = clean.replace(value, "<скрыто>")
    return clean.strip()


def _safe_field(value: Any, *, fallback: str = "", limit: int = 160) -> str:
    clean = redact_runtime_log(str(value or ""))
    clean = " ".join(clean.split())[:limit]
    return clean or fallback


def _endpoint(host: str, port: int) -> str:
    clean_host = _safe_field(host, fallback="unknown", limit=255)
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = f"[{clean_host}]"
    return f"{clean_host}:{max(0, int(port))}"


@dataclass(frozen=True, slots=True)
class RuntimeNodeIdentity:
    ref: str
    name: str
    endpoint: str
    protocol: str

    @classmethod
    def from_node(cls, node: Any) -> "RuntimeNodeIdentity":
        node_id = str(getattr(node, "id", "") or "")
        ref = hashlib.sha256(node_id.encode("utf-8")).hexdigest()[:12] if node_id else "unknown"
        return cls(
            ref=ref,
            name=_safe_field(getattr(node, "name", ""), fallback="без имени"),
            endpoint=_endpoint(
                str(getattr(node, "server", "") or ""),
                int(getattr(node, "port", 0) or 0),
            ),
            protocol=_safe_field(getattr(node, "scheme", ""), fallback="unknown", limit=40),
        )

    def fields(self) -> str:
        return (
            f"node={json.dumps(self.name, ensure_ascii=False)} "
            f"node_ref={self.ref} endpoint={self.endpoint} protocol={self.protocol}"
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
