"""Loopback relay readiness — the shared seam between sing-box and each core."""

from __future__ import annotations

import socket
import time
from typing import Callable

from ...application.async_steps import TransitionSteps, run_in_worker, sleep_ms
from ...constants import PROXY_HOST
from ...platform.windows.subprocess_utils import sleep_with_events


def probe_loopback_relay(port: int, *, host: str = PROXY_HOST, connect_timeout: float = 0.15) -> bool:
    """One blocking accept probe (worker-only)."""
    try:
        with socket.create_connection((host, int(port)), timeout=connect_timeout):
            return True
    except OSError:
        return False


def wait_for_loopback_relay_steps(
    port: int,
    *,
    host: str = PROXY_HOST,
    timeout: float = 10.0,
    should_continue: Callable[[], bool] | None = None,
    connect_timeout: float = 0.15,
    step: float = 0.05,
) -> TransitionSteps:
    """Step version of :func:`wait_for_loopback_relay` for transitions.

    Every connect attempt runs in the worker pool; ``should_continue`` is
    evaluated on the GUI thread between attempts, so it may read QProcess
    and controller state.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        if should_continue is not None and not should_continue():
            return False
        if (yield run_in_worker(
            lambda: probe_loopback_relay(port, host=host, connect_timeout=connect_timeout)
        )):
            return True
        yield sleep_ms(int(step * 1000))
    return False


def wait_for_loopback_relay(
    port: int,
    *,
    host: str = PROXY_HOST,
    timeout: float = 10.0,
    should_continue: Callable[[], bool] | None = None,
    connect_timeout: float = 0.15,
    step: float = 0.05,
) -> bool:
    """Wait until a core's local SOCKS relay accepts a loopback TCP connection.

    Returns ``True`` as soon as a connection succeeds, ``False`` if the deadline
    passes or ``should_continue`` reports the attempt should be abandoned (e.g.
    the owned process died or the transition was superseded). No payload is
    sent — this only proves the listener is bound and accepting, which is the
    precondition the sing-box front relies on before dialing the relay.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        if should_continue is not None and not should_continue():
            return False
        try:
            with socket.create_connection((host, int(port)), timeout=connect_timeout):
                return True
        except OSError:
            sleep_with_events(step)
    return False
