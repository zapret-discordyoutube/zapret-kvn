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


if __name__ == "__main__":
    unittest.main()
