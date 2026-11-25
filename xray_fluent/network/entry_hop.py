"""WARP entry hop switch for the probes (owner decision 2026-11-25).

With the hop on, every connection to our server must enter through WARP so the provider never sees the server address
(owner rule, also "probes must not expose servers").  Pings and speed tests start their own temporary cores that dial
the server directly, outside the live tunnel, so they would show that address.  Until they get a way in through the hop
they are not made, and the reason is shown instead.  The probe of the ACTIVE proxy runs inside the live core and enters
through the hop by itself, so it is unaffected.
"""

from __future__ import annotations

REFUSAL = (
    "Замер сервера идёт мимо входа через WARP и показал бы адрес сервера провайдеру. "
    "Выключите вход через WARP, чтобы замерить"
)

_active = False


def configure(enabled: bool) -> None:
    global _active
    _active = bool(enabled)


def active() -> bool:
    return _active
