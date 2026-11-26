"""WARP account registration (owner decision 2026-11-25): the pieces that need no network, on real TLS bytes."""
from __future__ import annotations

from pathlib import Path
import ssl
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xray_fluent.network import warp_registration as registration  # noqa: E402


def real_client_hello() -> bytes:
    """The first bytes the real TLS stack sends for the API host."""
    outgoing = ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=registration.API_HOST)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class WarpRegistrationTests(unittest.TestCase):
    def test_the_split_point_is_inside_the_server_name_of_a_real_client_hello(self) -> None:
        hello = real_client_hello()
        name = hello.find(registration.API_HOST.encode())
        self.assertGreater(name, 0)
        cut = registration._name_offset(hello)
        self.assertGreater(cut, name)
        self.assertLess(cut, name + len(registration.API_HOST))

    def test_a_missing_or_partial_account_file_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "profile.json"
            self.assertFalse(registration.account_file_ready(path))
            path.write_text('{"private_key": "x"}', encoding="utf-8")
            self.assertFalse(registration.account_file_ready(path))
            path.write_text("not json", encoding="utf-8")
            self.assertFalse(registration.account_file_ready(path))

    def test_the_registration_key_is_a_real_wireguard_key_pair(self) -> None:
        import base64

        private, public = registration._new_key()
        self.assertEqual(32, len(base64.b64decode(private)))
        self.assertEqual(32, len(base64.b64decode(public)))
        self.assertNotEqual(private, public)

    def test_a_network_that_swallows_every_packet_cannot_stall_the_connect(self) -> None:
        # Field report 2026-11-26 (Windows 0.8.121): the API was blocked, every route ran into its own timeout and the
        # sum passed the 60 s the connect allows for this step, so the connect failed.  A black hole is a real network
        # behaviour: 192.0.2.1 (TEST-NET-1, reserved for documentation) never answers.
        import time
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as folder, patch.object(registration, "API_HOST", "192.0.2.1"), patch.object(
            registration, "KNOWN_ADDRESSES", ()
        ):
            started = time.monotonic()
            outcome = registration.ensure_account(Path(folder) / "account.json", timeout=8.0, budget=5.0)
            elapsed = time.monotonic() - started
        self.assertFalse(outcome.ok)
        self.assertLess(elapsed, 7.0, f"the registration took {elapsed:.1f} s with a budget of 5 s")


if __name__ == "__main__":
    unittest.main()
