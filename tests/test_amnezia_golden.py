import json
from pathlib import Path
import unittest

from xray_fluent.importer.link_parser import LinkParseError, parse_single

GOLDEN = Path(__file__).resolve().parents[1] / "runtime/amnezia/testdata/wg_awg_golden.json"


class AmneziaGoldenTests(unittest.TestCase):
    def test_import_preserves_the_shared_native_transport(self):
        for vector in json.loads(GOLDEN.read_text())["vectors"]:
            with self.subTest(vector=vector["id"]):
                if not vector["valid"]:
                    with self.assertRaises(LinkParseError):
                        parse_single(vector["conf"])
                    continue
                self.assertEqual(parse_single(vector["conf"]).outbound, vector["endpoint"])
