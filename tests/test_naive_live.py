"""Live: a real NaiveProxy key brings a real page through the real planner, the real sing-box front and the stock naive.exe.

Owner decision 2026-11-25 (tests on real data) and 2026-11-27 (stock naive is the core). The key is the canary key of the
naive bot session (tests/real_naive_key.py); the run needs Windows, ``core/naive.exe`` and ``core/sing-box.exe`` of the
build. Proxy mode, so no route of the machine changes. Nothing here prints the key, the server name or an address.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

_existing = QApplication.instance()
app = _existing if isinstance(_existing, QApplication) else (_existing or QApplication([]))

from tests import real_naive_key
from xray_fluent.constants import NAIVE_PATH_DEFAULT, SINGBOX_PATH_DEFAULT
from xray_fluent.engines.naive.manager import NaiveManager
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_proxy_runtime
from xray_fluent.importer.link_parser import parse_single

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "data" / "templates" / "sing-box" / "default.json"
_RUNNABLE = os.name == "nt" and NAIVE_PATH_DEFAULT.is_file() and SINGBOX_PATH_DEFAULT.is_file() and real_naive_key.available()


def _listening(port: int) -> bool:
    import socket

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


@unittest.skipUnless(_RUNNABLE, "needs Windows, core/naive.exe, core/sing-box.exe and the real NaiveProxy test key")
class NaiveLiveTests(unittest.TestCase):
    def test_a_real_key_brings_a_real_page_through_the_front_and_the_stock_client(self) -> None:
        node = parse_single(real_naive_key.key_line())
        document = parse_singbox_document(TEMPLATE_PATH, TEMPLATE_PATH.read_text(encoding="utf-8"))
        plan = plan_singbox_proxy_runtime(document, node)
        self.assertEqual("naive_sidecar", plan.outcome)
        sidecar = plan.naive_sidecar

        manager = NaiveManager()
        logs: list[str] = []
        manager.log_received.connect(logs.append)
        started = manager.start(
            sidecar.config, sidecar.relay_port, relay_username=sidecar.relay_username,
            relay_password=sidecar.relay_password, context=sidecar.context, secrets=sidecar.secrets,
            server_host=sidecar.server_host,
        )
        self.assertTrue(started, "the stock client did not bring the key's tunnel up: " + " | ".join(logs[-5:]))
        self.assertTrue(manager.is_running)

        front = None
        directory = tempfile.mkdtemp(prefix="zkvn-naive-live-")
        try:
            config_path = Path(directory) / "singbox.json"
            import json

            config_path.write_text(json.dumps(plan.singbox_config), encoding="utf-8")
            check = subprocess.run(
                [str(SINGBOX_PATH_DEFAULT), "check", "-c", str(config_path)],
                cwd=str(SINGBOX_PATH_DEFAULT.parent), capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(0, check.returncode, "sing-box rejected the plan: " + check.stderr[-400:])
            front = subprocess.Popen(
                [str(SINGBOX_PATH_DEFAULT), "run", "-c", str(config_path)],
                cwd=str(SINGBOX_PATH_DEFAULT.parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not _listening(plan.http_port):
                time.sleep(0.3)
            self.assertTrue(_listening(plan.http_port), "the front did not open its HTTP proxy port")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({
                    "http": f"http://127.0.0.1:{plan.http_port}", "https": f"http://127.0.0.1:{plan.http_port}",
                })
            )
            statuses = []
            for url in ("http://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204"):
                with opener.open(url, timeout=40) as reply:
                    statuses.append(reply.status)
            self.assertEqual([204, 204], statuses)
            # The helper stays alive for the session and is the one process that holds the tunnel.
            self.assertTrue(manager.is_running)
        finally:
            if front is not None:
                front.kill()
                front.wait(10)
            manager.stop()
            self.assertFalse(manager.process_alive)
            import shutil

            shutil.rmtree(directory, ignore_errors=True)
        self.assertFalse(any("naive" in line.lower() and "secret" in line.lower() for line in logs))
        key_secret = real_naive_key.key_line().split("@")[0].rsplit(":", 1)[-1]
        self.assertFalse(any(key_secret in line for line in logs), "the secret reached a log line")


if __name__ == "__main__":
    unittest.main()
