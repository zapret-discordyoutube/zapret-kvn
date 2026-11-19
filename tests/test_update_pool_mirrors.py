"""Updates from Forgejo mirrors under the zapret-links pool domains (owner 2026-11-19).

Russia cuts the whole zone zapret.moe by name (SNI); zapret-links serves the same Forgejo under random names of
other pool domains. The shared update core (``zapret_update/mirrors.py``, synced from Zapret 2 GUI) learns them
from ``/_sites/mirrors.json`` and its ``domains``; the KVN updater must then trust release files on them.
"""

import json
import unittest

from zapret_update import mirrors
from xray_fluent.updates.app_updater import _is_trusted_release_url

# The shape of /_sites/mirrors.json of 2026-11-19 (zapret.moe names flagged blocked from Russia).
MIRRORS = {
    "schema": 1,
    "domains": ["zapret.moe", "fuckingspeedtest.com", "osjcpjzipyb.click"],
    "families": {
        "git": {
            "preferred": "vaavlvfila.fuckingspeedtest.com",
            "names": [
                {"name": "git.zapret.moe", "blocked": True},
                {"name": "vaavlvfila.fuckingspeedtest.com", "blocked": False},
                {"name": "yhpwvzkvik.osjcpjzipyb.click", "blocked": False},
                {"name": "adrlneccyo.fuckingspeedtest.com", "blocked": False},
                {"name": "git2.zapret.moe", "blocked": True},
            ],
        },
        "wiki": {"preferred": "", "names": []},
    },
}


class PoolMirrorTests(unittest.TestCase):
    def test_only_pool_names_answer_and_their_release_files_are_trusted(self) -> None:
        asked: list[str] = []

        def fetch(url: str) -> bytes | None:
            asked.append(url)
            host = mirrors.host_of(url)
            if host.endswith(".zapret.moe"):
                raise OSError("cut by SNI")
            return json.dumps(MIRRORS).encode()

        names = mirrors.MirrorList(fetch, report=lambda _line: None)
        best = names.best()
        self.assertFalse(best.endswith(".zapret.moe"))
        hosts = names.hosts()
        self.assertEqual(best, hosts[0])                       # the name that won the race goes first
        self.assertIn("vaavlvfila.fuckingspeedtest.com", hosts)
        # A domain the program does not know by itself is learnt from `domains` of the list.
        self.assertIn("yhpwvzkvik.osjcpjzipyb.click", hosts)
        for host in ("vaavlvfila.fuckingspeedtest.com", "yhpwvzkvik.osjcpjzipyb.click", "adrlneccyo.fuckingspeedtest.com"):
            with self.subTest(host=host):
                self.assertTrue(mirrors.is_git_host(host))
                self.assertTrue(_is_trusted_release_url(
                    f"https://{host}/zapretkvn/zapret-kvn/releases/download/v0.8.90/ZapretKVN-v0.8.90-windows-x64.zip"
                ))
        # Names outside the listed domains stay foreign.
        self.assertFalse(_is_trusted_release_url(
            "https://evil.example/zapretkvn/zapret-kvn/releases/download/v0.8.90/ZapretKVN-v0.8.90-windows-x64.zip"
        ))
        self.assertFalse(mirrors.is_git_host("a.b.osjcpjzipyb.click"))

    def test_the_seed_starts_with_pool_names(self) -> None:
        seed = mirrors.bootstrap_hosts("git")
        self.assertFalse(seed[0].endswith(".zapret.moe"))
        self.assertEqual("git.zapret.moe", seed[-1])


if __name__ == "__main__":
    unittest.main()
