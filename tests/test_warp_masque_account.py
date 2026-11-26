"""The MASQUE account the app registers itself (owner 2026-11-26): the key formats the core reads, and the real API.

The key checks run the real OpenSSL parser on the key the app generates (Go reads the same DER): a wrong layout would only
show up when the core fails to start MASQUE on a machine.  The real registration creates two devices at Cloudflare, so it
runs only with `KVN_REAL_WARP=1` (the release gate does not hammer the API); a skipped test is an honest "unproven here".
Nothing here prints an address, a token or a key.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from xray_fluent.network import warp_masque_account as masque

_OPENSSL = shutil.which("openssl")


def _openssl(*arguments: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([_OPENSSL, *arguments], input=data, capture_output=True, check=False)


@unittest.skipUnless(_OPENSSL, "openssl is not here")
class KeyFormatTests(unittest.TestCase):
    def test_the_private_key_is_the_121_byte_sec1_structure_openssl_reads_as_p256(self) -> None:
        for _ in range(10):
            private, _public = masque.new_key()
            self.assertEqual(121, len(private))
            reply = _openssl("ec", "-inform", "DER", "-noout", "-text", data=private)
            self.assertEqual(0, reply.returncode, reply.stderr[:200])
            self.assertIn(b"prime256v1", reply.stdout + reply.stderr)

    def test_the_public_key_sent_to_the_api_is_the_x509_form_of_the_private_keys_own_point(self) -> None:
        private, public = masque.new_key()
        reply = _openssl("ec", "-inform", "DER", "-pubout", "-outform", "DER", data=private)
        self.assertEqual(0, reply.returncode)
        self.assertEqual(public, reply.stdout)


class AccountFileTests(unittest.TestCase):
    def test_an_address_of_the_api_answer_becomes_the_host_the_core_dials(self) -> None:
        self.assertEqual("162.159.198.2", masque.host_of("162.159.198.2:0"))
        self.assertEqual("2606:4700:103::2", masque.host_of("[2606:4700:103::2]:0"))
        self.assertEqual("", masque.host_of(""))

    def test_the_file_beside_the_wireguard_account_has_the_names_the_core_reads(self) -> None:
        self.assertEqual("C:/x/warp-entry-profile.json.masque", masque.account_path("C:/x/warp-entry-profile.json").as_posix())

    def test_a_file_without_a_key_or_an_address_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.masque"
            self.assertFalse(masque.ready(path))
            path.write_text(json.dumps({"private_key": "x"}), encoding="utf-8")
            self.assertFalse(masque.ready(path))


class RealRegistrationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("KVN_REAL_WARP") == "1", "set KVN_REAL_WARP=1 to register real devices")
    def test_the_real_api_registers_a_masque_account_over_the_apps_own_routes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            account = Path(directory) / "warp-entry-profile.json"
            masque.forget_failure()
            outcome = masque.ensure(account)
            self.assertTrue(outcome.ok, f"{outcome.route}: {outcome.detail}")
            file = masque.account_path(account)
            self.assertTrue(masque.ready(file))
            document = json.loads(file.read_text(encoding="utf-8"))
            self.assertEqual(
                {"private_key", "endpoint_v4", "endpoint_v6", "endpoint_h2_v4", "endpoint_h2_v6", "endpoint_pub_key",
                 "license", "id", "access_token", "ipv4", "ipv6"},
                set(document),
            )
            self.assertTrue(document["endpoint_pub_key"].startswith("-----BEGIN PUBLIC KEY-----"))
            self.assertEqual(121, len(base64.b64decode(document["private_key"])))
            self.assertNotIn(":", document["endpoint_v4"])
            self.assertEqual("cached", masque.ensure(account).route)
            keep = os.environ.get("KVN_REAL_WARP_KEEP")
            if keep:
                shutil.copyfile(file, keep)


if __name__ == "__main__":
    unittest.main()
