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
