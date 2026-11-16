"""Masking ("Маскировка") data model, shared field for field with Android `:masking`.

Every section is optional and a missing section means "do nothing", never "defaults".
Ownership (workspace AGENTS.md, native cores): `xray` goes to Xray-core, `wireguard` to the
Amnezia core, `singbox` to sing-box's own TLS client for the protocols sing-box owns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

SCHEMA = 1
SIGNATURE_KEYS = ("i1", "i2", "i3", "i4", "i5")
UDP443_MODES = ("reject", "allow", "skip")


@dataclass(frozen=True, slots=True)
class Span:
    """A number or an inclusive range as Xray writes it: "16" or "8-16"; never negative."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.start > self.end:
            raise ValueError("invalid range")

    @classmethod
    def of(cls, value: int) -> Span:
        return cls(value, value)

    @classmethod
    def parse(cls, text: str) -> Span | None:
        parts = [part.strip() for part in str(text).strip().split("-")]
        if not parts or len(parts) > 2 or any(not part.isdigit() or not part.isascii() for part in parts):
            return None
        start, end = int(parts[0]), int(parts[-1])
        return cls(start, end) if start <= end else None

    def __str__(self) -> str:
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


@dataclass(frozen=True, slots=True)
class WireGuardMasking:
    """Junk packets and I1-I5: sent by the initiator only, so they work with a plain WG server.

    H1-H4 / S1-S4 are deliberately absent: they must equal the server's values.
    """

    enabled: bool = True
    jc: int | None = None
    jmin: int | None = None
    jmax: int | None = None
    signatures: dict[str, str] = field(default_factory=dict)

    @property
    def has_junk(self) -> bool:
        return self.jc is not None or self.jmin is not None or self.jmax is not None


@dataclass(frozen=True, slots=True)
class MuxCool:
    enabled: bool = True
    concurrency: int = 8
    xudp_concurrency: int = 16
    xudp_proxy_udp443: str = "reject"


@dataclass(frozen=True, slots=True)
class Xmux:
    max_concurrency: Span | None = None
    max_connections: Span | None = None
    c_max_reuse_times: Span | None = None
    h_max_request_times: Span | None = None
    h_max_reusable_secs: Span | None = None
    h_keep_alive_period: int | None = None


@dataclass(frozen=True, slots=True)
class XrayFragment:
    enabled: bool = True
    packets: str = "tlshello"
    length: Span = Span(100, 200)
    delay: Span = Span(10, 20)
    max_split: Span | None = None


@dataclass(frozen=True, slots=True)
class Desync:
    """Packet tricks on the TCP socket to the VPN server (same as Android `Desync`, executed by the
    app's own dialer: Android core patch 0017 `kvndesync`). fake | disorder | split | oob."""

    enabled: bool = True
    method: str = "fake"
    split_at: str = "sni"
    fake_ttl: int = 3
    fake_sni: str = "vk.com"


DESYNC_METHODS = ("fake", "disorder", "split", "oob")
DESYNC_MAX_OFFSET = 1400
DESYNC_MAX_TTL = 32
DESYNC_SAFE_TTL = 8


@dataclass(frozen=True, slots=True)
class XrayShaping:
    enabled: bool = True
    mux: MuxCool | None = None
    xmux: Xmux | None = None
    fragment: XrayFragment | None = None
    desync: Desync | None = None


@dataclass(frozen=True, slots=True)
class SingboxFragment:
    enabled: bool = True
    fragment: bool = True
    record_fragment: bool = False
    fallback_delay_ms: int | None = None


@dataclass(frozen=True, slots=True)
class Masking:
    wireguard: WireGuardMasking | None = None
    xray: XrayShaping | None = None
    singbox: SingboxFragment | None = None

    @property
    def is_empty(self) -> bool:
        return self.wireguard is None and self.xray is None and self.singbox is None


NONE = Masking()


class OverrideKind(str, Enum):
    INHERIT = "inherit"
    OFF = "off"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class MaskingOverride:
    kind: OverrideKind = OverrideKind.INHERIT
    masking: Masking = NONE


INHERIT = MaskingOverride()
OFF = MaskingOverride(OverrideKind.OFF)


@dataclass(frozen=True, slots=True)
class MaskingSettings:
    enabled: bool = False
    global_masking: Masking = NONE
    overrides: dict[str, MaskingOverride] = field(default_factory=dict)

    def override_for(self, server_key: str | None) -> MaskingOverride:
        return self.overrides.get(server_key, INHERIT) if server_key else INHERIT

    def with_trial(self, server_key: str, override: MaskingOverride) -> MaskingSettings:
        """The settings one "Подбор" step runs with: ``override`` for ``server_key`` only, never
        stored. With the master switch off every other server stays unmasked."""
        if self.enabled:
            return MaskingSettings(True, self.global_masking, {**self.overrides, server_key: override})
        return MaskingSettings(True, NONE, {server_key: override})


SETTINGS_OFF = MaskingSettings()


class Core(str, Enum):
    XRAY = "xray"
    AMNEZIA = "amnezia"
    HYSTERIA = "hysteria"
    SINGBOX = "sing-box"


_MULTIPLEXED = {"xhttp", "splithttp", "grpc", "h2", "http"}
_TCP_STREAMS = {"tcp", "raw", "ws", "httpupgrade", "xhttp", "splithttp", "grpc", "h2", "http"}


@dataclass(frozen=True, slots=True)
class ServerShape:
    core: Core
    protocol: str
    network: str | None = None
    security: str | None = None
    flow: str | None = None

    @property
    def is_vision(self) -> bool:
        return bool(self.flow) and self.flow.startswith("xtls-rprx-vision")

    @property
    def is_multiplexed_transport(self) -> bool:
        return self.network in _MULTIPLEXED

    @property
    def is_xhttp(self) -> bool:
        return self.network in {"xhttp", "splithttp"}

    @property
    def is_tcp_stream(self) -> bool:
        return self.network is None or self.network in _TCP_STREAMS


@dataclass(frozen=True, slots=True)
class Problem:
    """A validation finding; `message` is shown to the user as is (Russian UI)."""

    field: str
    message: str
    error: bool = True


def errors(problems: list[Problem]) -> list[Problem]:
    return [problem for problem in problems if problem.error]
