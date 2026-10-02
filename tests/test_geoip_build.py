"""GeoIP assets are pinned and downloaded only by build tooling."""
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scripts import prepare_geoip


class GeoipBuildTests(unittest.TestCase):
    def test_refresh_pins_latest_official_snapshot_and_stage_reuses_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cache=root/'cache';lock_path=root/'lock.json'
            data=b'MMDB-test-payload';archive=gzip.compress(data)
            def fetch(url,path):
                if url == prepare_geoip.SOURCE_PAGE:
                    path.write_text('https://download.db-ip.com/free/dbip-country-lite-2026-08.mmdb.gz https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz')
                else:
                    self.assertTrue(url.endswith('2026-09.mmdb.gz'));path.write_bytes(archive)
            with patch.object(prepare_geoip,'CACHE',cache),patch.object(prepare_geoip,'LOCK_PATH',lock_path),patch.object(prepare_geoip,'fetch',side_effect=fetch),patch.object(prepare_geoip,'verify_database',return_value=['US']):
                lock=prepare_geoip.refresh()
                self.assertEqual(lock['version'],'2026-09')
                self.assertEqual(lock['sha256'],hashlib.sha256(data).hexdigest())
                assets=root/'assets';(assets/'flags').mkdir(parents=True)
                source=Path(__file__).resolve().parents[1]/'assets/flags/us.png'
                (assets/'flags/us.png').write_bytes(source.read_bytes())
                before=lock_path.read_bytes()
                with patch.object(prepare_geoip,'fetch',side_effect=AssertionError('cached build must not download')):
                    prepare_geoip.stage(assets)
                self.assertEqual((assets/'geoip/country.mmdb').read_bytes(),data)
                self.assertEqual(before,lock_path.read_bytes())
                (assets/'geoip/country.mmdb').write_bytes(b'corrupted')
                with self.assertRaisesRegex(ValueError,'differs from lock'):
                    prepare_geoip.verify_payload(assets)

    def test_unknown_or_changed_download_source_is_rejected(self):
        lock=json.loads(prepare_geoip.LOCK_PATH.read_text())
        lock['url']='https://example.com/database.mmdb.gz'
        with self.assertRaises(ValueError):prepare_geoip.verify_lock(lock)


class GeoipFetchRetryTests(unittest.TestCase):
    def test_reset_mid_transfer_restarts_the_download(self):
        import io
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        class Broken(io.BytesIO):
            def read(self, *_args):
                raise ConnectionResetError(104, "Connection reset by peer")

        responses = [Broken(b"partial"), io.BytesIO(b"complete")]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            prepare_geoip, "urlopen", side_effect=lambda *_a, **_k: responses.pop(0)
        ), patch.object(prepare_geoip.shutil, "which", return_value=None), patch.object(
            prepare_geoip.time, "sleep"
        ):
            target = Path(directory) / "db"
            prepare_geoip.fetch("https://example.invalid/db", target)
            self.assertEqual(target.read_bytes(), b"complete")
        self.assertEqual(responses, [])

    def test_curl_downloads_when_available_and_retries_a_reset(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(56, command, stderr=b"Connection reset by peer")
            Path(command[command.index("--output") + 1]).write_bytes(b"complete")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            prepare_geoip.shutil, "which", return_value="/usr/bin/curl"
        ), patch.object(prepare_geoip.subprocess, "run", side_effect=run), patch.object(
            prepare_geoip, "urlopen", side_effect=AssertionError("curl must be used")
        ), patch.object(prepare_geoip.time, "sleep"):
            target = Path(directory) / "db"
            prepare_geoip.fetch("https://example.invalid/db", target)
            self.assertEqual(target.read_bytes(), b"complete")
        self.assertEqual(len(calls), 2)

    def test_curl_http_error_is_not_retried(self):
        import subprocess
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        run = patch.object(
            prepare_geoip.subprocess, "run",
            side_effect=subprocess.CalledProcessError(22, ["curl"], stderr=b"404"),
        )
        with tempfile.TemporaryDirectory() as directory, patch.object(
            prepare_geoip.shutil, "which", return_value="/usr/bin/curl"
        ), run as mocked, patch.object(prepare_geoip.time, "sleep"):
            with self.assertRaises(OSError):
                prepare_geoip.fetch("https://example.invalid/db", Path(directory) / "db")
        self.assertEqual(mocked.call_count, 1)
