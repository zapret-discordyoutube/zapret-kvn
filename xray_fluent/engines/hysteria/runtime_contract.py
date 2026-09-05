from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
import time
from typing import Callable, Iterable, Protocol
from urllib.parse import parse_qsl, unquote, urlsplit

from ...diagnostics.runtime_errors import classify_core_error


class HysteriaExecutionKind(str, Enum):
    NATIVE = "native"
    OFFICIAL_HYSTERIA_SIDECAR = "official_hysteria_sidecar"
    UNSUPPORTED = "unsupported"


class HysteriaSwitchKind(str, Enum):
    NATIVE_HOT_SWITCH = "native_hot_switch"
    FULL_SIDECAR_TRANSITION = "full_sidecar_transition"
    UNSUPPORTED = "unsupported"


class HysteriaRuntimeState(str, Enum):
    IDLE = "IDLE"
    PLANNING = "PLANNING"
    STARTING_FRONT = "STARTING_FRONT"
    STARTING_SIDECAR = "STARTING_SIDECAR"
    WAITING_RELAY = "WAITING_RELAY"
    READY = "READY"
    SWITCH_REQUESTED = "SWITCH_REQUESTED"
    PREPARING_REPLACEMENT = "PREPARING_REPLACEMENT"
    REPLACEMENT_READY = "REPLACEMENT_READY"
    COMMITTING_SWITCH = "COMMITTING_SWITCH"
    STOPPING_OLD = "STOPPING_OLD"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"


class HysteriaFailureCode(str, Enum):
    CORE_UNCLASSIFIED = "CORE_UNCLASSIFIED"
    LOCAL_RELAY_AUTH_REJECTED = "LOCAL_RELAY_AUTH_REJECTED"
    LOCAL_SOCKET_PROTECTION_FAILED = "LOCAL_SOCKET_PROTECTION_FAILED"
    TARGET_TLS_REJECTED = "TARGET_TLS_REJECTED"
    TARGET_CONNECTION_CLOSED = "TARGET_CONNECTION_CLOSED"
    TARGET_NETWORK_TIMEOUT = "TARGET_NETWORK_TIMEOUT"
    TARGET_CONNECTION_REFUSED = "TARGET_CONNECTION_REFUSED"
    TARGET_TLS_INTERNAL = "TARGET_TLS_INTERNAL"
    TARGET_TLS_UNKNOWN_AUTHORITY = "TARGET_TLS_UNKNOWN_AUTHORITY"
    TARGET_PIN_MISMATCH = "TARGET_PIN_MISMATCH"
    TARGET_AUTH_REJECTED = "TARGET_AUTH_REJECTED"
    TARGET_OBFS_REJECTED = "TARGET_OBFS_REJECTED"
    LOCAL_CONFIG_INVALID = "LOCAL_CONFIG_INVALID"
    LOCAL_RUNTIME_UNSUPPORTED = "LOCAL_RUNTIME_UNSUPPORTED"
    LOCAL_BIND_COLLISION = "LOCAL_BIND_COLLISION"
    LOCAL_PROCESS_START_FAILED = "LOCAL_PROCESS_START_FAILED"
    LOCAL_PROCESS_EXITED = "LOCAL_PROCESS_EXITED"
    LOCAL_RELAY_NOT_READY = "LOCAL_RELAY_NOT_READY"
    LOCAL_RELAY_DIED = "LOCAL_RELAY_DIED"
    LOCAL_FRONT_NOT_READY = "LOCAL_FRONT_NOT_READY"
    LOCAL_CONTROL_PLANE_UNAVAILABLE = "LOCAL_CONTROL_PLANE_UNAVAILABLE"
    TARGET_NOT_IN_ACTIVE_POOL = "TARGET_NOT_IN_ACTIVE_POOL"
    TARGET_RUNTIME_INCOMPATIBLE = "TARGET_RUNTIME_INCOMPATIBLE"
    NO_COMPATIBLE_FALLBACK = "NO_COMPATIBLE_FALLBACK"
    TRANSITION_STALE_GENERATION = "TRANSITION_STALE_GENERATION"
    TRANSITION_DEADLINE_EXCEEDED = "TRANSITION_DEADLINE_EXCEEDED"
    TRANSITION_ROLLBACK_FAILED = "TRANSITION_ROLLBACK_FAILED"


AUTOMATIC_SWITCH_FAILURES = frozenset(
    {
        HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
        HysteriaFailureCode.TARGET_CONNECTION_REFUSED,
        HysteriaFailureCode.LOCAL_PROCESS_EXITED,
        HysteriaFailureCode.LOCAL_RELAY_DIED,
        HysteriaFailureCode.LOCAL_RELAY_NOT_READY,
        HysteriaFailureCode.LOCAL_CONTROL_PLANE_UNAVAILABLE,
    }
)

SECURITY_FAILURES = frozenset(
    {
        HysteriaFailureCode.TARGET_TLS_REJECTED,
        HysteriaFailureCode.TARGET_TLS_INTERNAL,
        HysteriaFailureCode.TARGET_TLS_UNKNOWN_AUTHORITY,
        HysteriaFailureCode.TARGET_PIN_MISMATCH,
        HysteriaFailureCode.TARGET_AUTH_REJECTED,
        HysteriaFailureCode.TARGET_OBFS_REJECTED,
    }
)


@dataclass(frozen=True, slots=True)
class HysteriaCapability:
    protocol: str
    execution_kind: HysteriaExecutionKind
    obfs_kind: str
    tls_kind: str
    endpoint_kind: str
    switch_kind: HysteriaSwitchKind
    runtime_requirements: frozenset[str]
    valid: bool
    failure_code: HysteriaFailureCode | None = None
    validation_message: str = ""

    @property
    def semantic_key(self) -> tuple[str, str, str, str, tuple[str, ...], bool]:
        """Platform-independent part used by Windows/Android golden vectors."""

        return (
            self.protocol,
            self.obfs_kind,
            self.tls_kind,
            self.endpoint_kind,
            tuple(sorted(self.runtime_requirements)),
            self.valid,
        )


@dataclass(slots=True)
class HysteriaRuntimeSession:
    session_generation: int = 0
    selected_node_id: str | None = None
    runtime_kind: str = ""
    sidecar_kind: str = ""
    sidecar_process_generation: int = 0
    relay_host: str = "127.0.0.1"
    relay_port: int = 0
    relay_credentials_generation: int = 0
    front_process_generation: int = 0
    front_target_generation: int = 0
    outbound_pool_tags: tuple[str, ...] = ()
    started_at_monotonic: float = 0.0
    ready_at_monotonic: float = 0.0
    failure_episode_id: int = 0
    last_failure_code: HysteriaFailureCode | None = None
    automatic_switch_attempted: bool = False
    state: HysteriaRuntimeState = HysteriaRuntimeState.IDLE


@dataclass(slots=True)
class HysteriaTransitionContract:
    """Small reducer shared by controller operations and deterministic tests."""

    session: HysteriaRuntimeSession = field(default_factory=HysteriaRuntimeSession)

    def begin(
        self,
        generation: int,
        node_id: str | None,
        runtime_kind: str,
        *,
        preserve_failure_episode: bool = False,
    ) -> None:
        previous = self.session
        self.session = HysteriaRuntimeSession(
            session_generation=generation,
            selected_node_id=node_id,
            runtime_kind=runtime_kind,
            sidecar_kind="hysteria" if runtime_kind == "official_hysteria_sidecar" else "",
            started_at_monotonic=time.monotonic(),
            failure_episode_id=(previous.failure_episode_id if preserve_failure_episode else 0),
            last_failure_code=(previous.last_failure_code if preserve_failure_episode else None),
            automatic_switch_attempted=(
                previous.automatic_switch_attempted if preserve_failure_episode else False
            ),
            state=HysteriaRuntimeState.PLANNING,
        )

    def advance(self, state: HysteriaRuntimeState, *, generation: int) -> bool:
        if generation != self.session.session_generation:
            self.session.last_failure_code = HysteriaFailureCode.TRANSITION_STALE_GENERATION
            return False
        self.session.state = state
        if state is HysteriaRuntimeState.READY:
            self.session.ready_at_monotonic = time.monotonic()
        return True

    def fail(
        self,
        code: HysteriaFailureCode,
        *,
        generation: int,
        automatic_switch: bool,
    ) -> bool:
        if generation != self.session.session_generation:
            return False
        self.session.failure_episode_id += 1
        self.session.last_failure_code = code
        self.session.automatic_switch_attempted = automatic_switch
        self.session.state = HysteriaRuntimeState.SWITCH_REQUESTED if automatic_switch else HysteriaRuntimeState.FAILED
        return True

    def terminal(
        self,
        code: HysteriaFailureCode,
        *,
        generation: int,
        degraded: bool = False,
    ) -> bool:
        """Finish the current episode without counting a second failure episode."""

        if generation != self.session.session_generation:
            return False
        self.session.last_failure_code = code
        self.session.state = (
            HysteriaRuntimeState.DEGRADED if degraded else HysteriaRuntimeState.FAILED
        )
        return True


_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "t"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "f", ""})
_PIN_RE = re.compile(r"^[0-9a-f]{64}$")
_KNOWN_QUERY_KEYS = frozenset(
    {
        "auth",
        "sni",
        "insecure",
        "obfs",
        "obfspassword",
        "up",
        "down",
        "pinsha256",
        "ech",
        "hopinterval",
        "minpacketsize",
        "maxpacketsize",
    }
)


def _canonical_query_key(value: str) -> str:
    key = str(value or "").strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "servername": "sni",
        "peer": "sni",
        "allowinsecure": "insecure",
        "skipcertverify": "insecure",
        "obfspassword": "obfspassword",
        "upmbps": "up",
        "upbps": "up",
        "downmbps": "down",
        "downbps": "down",
    }
    return aliases.get(key, key)


_KNOWN_QUERY_KEYS = frozenset(
    {
        "auth",
        "sni",
        "insecure",
        "obfs",
        "obfspassword",
        "up",
        "down",
        "pinsha256",
        "ech",
        "hopinterval",
        "minpacketsize",
        "maxpacketsize",
    }
)
_MALFORMED_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _invalid(message: str, code: HysteriaFailureCode = HysteriaFailureCode.LOCAL_CONFIG_INVALID) -> HysteriaCapability:
    return HysteriaCapability(
        protocol="hysteria2",
        execution_kind=HysteriaExecutionKind.UNSUPPORTED,
        obfs_kind="none",
        tls_kind="ca",
        endpoint_kind="dns",
        switch_kind=HysteriaSwitchKind.UNSUPPORTED,
        runtime_requirements=frozenset({"raw_uri_required"}),
        valid=False,
        failure_code=code,
        validation_message=message,
    )


def classify_hysteria_uri(raw_uri: str, *, platform: str = "windows") -> HysteriaCapability:
    text = str(raw_uri or "")
    if not text or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in text):
        return _invalid("Hysteria2 URI contains whitespace or a control character")
    if _MALFORMED_PERCENT_RE.search(text):
        return _invalid("Hysteria2 URI has invalid percent encoding")
    try:
        parsed = urlsplit(text)
    except ValueError:
        return _invalid("Hysteria2 URI has invalid authority")
    if parsed.scheme.lower() not in {"hy2", "hysteria2"}:
        return _invalid("unsupported Hysteria2 URI scheme", HysteriaFailureCode.LOCAL_RUNTIME_UNSUPPORTED)
    try:
        host = unquote(parsed.hostname or "")
    except Exception:
        host = ""
    if not host or any(ord(character) < 32 or ord(character) == 127 for character in host):
        return _invalid("Hysteria2 URI has invalid server")

    authority = parsed.netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return _invalid("Hysteria2 URI has invalid IPv6 server")
        port_union = authority[closing + 1 :].removeprefix(":") or "443"
    else:
        if authority.count(":") > 1:
            return _invalid("Hysteria2 URI requires brackets around IPv6 server")
        port_union = authority.rsplit(":", 1)[1] if ":" in authority else "443"
    port_hopping = "," in port_union or "-" in port_union
    for part in port_union.split(","):
        bounds = part.split("-", 1)
        try:
            ports = [int(value) for value in bounds]
        except ValueError:
            return _invalid("Hysteria2 URI has invalid port union")
        if any(port < 1 or port > 65535 for port in ports) or len(ports) == 2 and ports[0] > ports[1]:
            return _invalid("Hysteria2 URI has invalid port union")

    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        return _invalid("Hysteria2 URI has invalid query")
    query: dict[str, str] = {}
    for raw_key, value in pairs:
        key = _canonical_query_key(raw_key)
        if any(ord(character) < 32 or ord(character) == 127 for character in key + value):
            return _invalid("Hysteria2 URI query contains a control character")
        if key in _KNOWN_QUERY_KEYS and key in query:
            return _invalid("Hysteria2 URI repeats a known query parameter")
        query[key] = value

    raw_authentication = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    authentication = unquote(raw_authentication or query.get("auth", ""))
    if not authentication:
        return _invalid("Hysteria2 URI is missing authentication")
    if any(ord(character) < 32 or ord(character) == 127 for character in authentication):
        return _invalid("Hysteria2 authentication contains a control character")

    insecure_text = query.get("insecure", "")
    if insecure_text.strip().lower() not in _TRUE_VALUES | _FALSE_VALUES:
        return _invalid("Hysteria2 URI has invalid insecure value")
    insecure = insecure_text.strip().lower() in _TRUE_VALUES
    raw_pin = query.get("pinsha256", "").strip().lower().replace(":", "").replace("-", "")
    if raw_pin and not _PIN_RE.fullmatch(raw_pin):
        return _invalid("Hysteria2 pinSHA256 must contain exactly 32 SHA-256 bytes")
    if insecure and not raw_pin:
        return _invalid("Hysteria2 insecure requires certificate pin")

    obfs = query.get("obfs", "").strip().lower()
    obfs_kind = "none" if obfs in {"", "none", "plain"} else obfs
    if obfs_kind not in {"none", "salamander", "gecko"}:
        return _invalid(
            f"Hysteria2 obfs '{obfs_kind}' is unsupported",
            HysteriaFailureCode.LOCAL_RUNTIME_UNSUPPORTED,
        )
    if obfs_kind != "none" and not query.get("obfspassword", ""):
        return _invalid(
            f"invalid hysteria2 link: {obfs_kind} obfs requires obfs-password"
        )

    try:
        parsed_ip = ipaddress.ip_address(host)
        endpoint_kind = "ipv4" if parsed_ip.version == 4 else "ipv6"
    except ValueError:
        endpoint_kind = "dns"
    runtime_requirements = {"raw_uri_required", "process_bypass_required"}
    if raw_pin:
        runtime_requirements.add("pin_required")
    if port_hopping:
        runtime_requirements.add("port_hopping_required")
    if platform == "android":
        execution_kind = HysteriaExecutionKind.NATIVE
        switch_kind = HysteriaSwitchKind.NATIVE_HOT_SWITCH
        runtime_requirements.discard("process_bypass_required")
    else:
        execution_kind = HysteriaExecutionKind.OFFICIAL_HYSTERIA_SIDECAR
        switch_kind = HysteriaSwitchKind.FULL_SIDECAR_TRANSITION
    return HysteriaCapability(
        protocol="hysteria2",
        execution_kind=execution_kind,
        obfs_kind=obfs_kind,
        tls_kind="pinned" if raw_pin else "ca",
        endpoint_kind=endpoint_kind,
        switch_kind=switch_kind,
        runtime_requirements=frozenset(runtime_requirements),
        valid=True,
    )


def classify_hysteria_failure(message: str, *, process_exited: bool = False) -> HysteriaFailureCode | None:
    code, action = classify_core_error(str(message or ""))
    if action == "record_only":
        return HysteriaFailureCode.LOCAL_PROCESS_EXITED if process_exited else None
    if code != "CORE_UNCLASSIFIED":
        return HysteriaFailureCode(code)
    if process_exited:
        return HysteriaFailureCode.LOCAL_PROCESS_EXITED
    return None


class _NodeLike(Protocol):
    id: str
    name: str
    group: str
    tags: list[str]


def node_is_maintenance(node: _NodeLike) -> bool:
    values = [node.name, node.group, *node.tags]
    normalized = {str(value or "").strip().casefold() for value in values}
    return bool(normalized & {"maintenance", "техработы", "обслуживание"})


def choose_compatible_fallback(
    nodes: Iterable[_NodeLike],
    *,
    failed_node_id: str,
    cooldown_until: dict[str, float],
    capability: Callable[[_NodeLike], HysteriaCapability],
    now: float | None = None,
) -> _NodeLike | None:
    current = time.monotonic() if now is None else now
    for node in nodes:
        if node.id == failed_node_id or node_is_maintenance(node):
            continue
        if cooldown_until.get(node.id, 0.0) > current:
            continue
        if capability(node).valid:
            return node
    return None
