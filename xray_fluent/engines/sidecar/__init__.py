"""Shared standard for local sidecar cores that sit behind the sing-box front.

Every native transport core (AmneziaWG, Hysteria2, xray) is launched as a local
loopback SOCKS relay that the sing-box front dials through — the front is the
sole OS-facing inbound, each core keeps its own clean protocol implementation.
The *seam* between the front and each core is identical regardless of protocol:
the loopback listener must accept a TCP connection before the front can use it.

This package holds that shared contract so each core manager stops
reimplementing it. Protocol-specific concerns (config handoff, handshake
detection, failure taxonomy, recovery policy) deliberately stay in each engine.
"""

from __future__ import annotations

from .readiness import wait_for_loopback_relay

__all__ = ["wait_for_loopback_relay"]
