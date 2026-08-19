"""Display-only helpers for screenshot-safe UI surfaces."""

from __future__ import annotations


MASKED_VALUE = "********"


def masked_endpoint() -> str:
    """Return the common placeholder used instead of a server endpoint."""
    return MASKED_VALUE
