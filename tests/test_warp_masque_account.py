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
import socket
import socketserver
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from xray_fluent.network import warp_masque_account as masque
from xray_fluent.network import warp_registration

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


class _ConnectProxy(socketserver.ThreadingTCPServer):
    """A plain HTTP CONNECT proxy that forwards the real bytes: the stand-in for the local port of a running VPN."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ConnectHandler)


class _ConnectHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            head += chunk
        target = head.split(b" ", 2)[1].decode()
        host, _, port = target.rpartition(":")
        upstream = socket.create_connection((host, int(port)), timeout=15)
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def pump(source: socket.socket, sink: socket.socket) -> None:
            try:
                while data := source.recv(16384):
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                for end in (source, sink):
                    try:
                        end.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(upstream, self.request), daemon=True).start()
        try:
            pump(self.request, upstream)
        finally:
            upstream.close()


class RealRegistrationThroughProxyTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("KVN_REAL_WARP") == "1", "set KVN_REAL_WARP=1 to register real devices")
    def test_both_accounts_are_registered_through_a_local_proxy_the_way_the_vpn_is_used(self) -> None:
        """The connect that runs without the hop registers the accounts through the VPN's local port (owner 2026-11-27).

        The proxy here forwards the real bytes to the real API, so the PATCH with the device token and the files are real;
        that a provider lets the tunnel through is proven only on the owner's network."""
        proxy = _ConnectProxy()
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{proxy.server_address[1]}"
            with tempfile.TemporaryDirectory() as directory:
                account = Path(directory) / "warp-entry-profile.json"
                masque.forget_failure()
                first = warp_registration.ensure_account(account, proxy_url=url, timeout=20.0)
                self.assertTrue(first.ok, f"{first.route}: {first.detail}")
                self.assertEqual("vpn", first.route)
                second = masque.ensure(account, proxy_url=url, timeout=20.0, budget=40.0)
                self.assertTrue(second.ok, f"{second.route}: {second.detail}")
                self.assertEqual("vpn", second.route)
                self.assertTrue(masque.ready(masque.account_path(account)))
        finally:
            proxy.shutdown()
            proxy.server_close()


if __name__ == "__main__":
    unittest.main()
