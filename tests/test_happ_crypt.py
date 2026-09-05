from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.serialization import load_der_private_key

from xray_fluent.importer.happ_crypt import (
    HappCryptError,
    decrypt_happ_link,
    is_happ_crypt_link,
)
from xray_fluent.importer.happ_keys import CRYPT1_4_KEYS, CRYPT5_KEYS
from xray_fluent.importer.subscription_http import SubscriptionFetchError, resolve_subscription_source


VECTORS = json.loads((Path(__file__).parent / "data" / "happ_vectors.json").read_text("utf-8"))


class HappKeyTableTests(unittest.TestCase):
    def test_pkcs1_table_covers_four_generations(self) -> None:
        self.assertEqual(len(CRYPT1_4_KEYS), 4)
        sizes = [
            load_der_private_key(base64.b64decode(encoded), None).key_size
            for encoded in CRYPT1_4_KEYS
        ]
        self.assertEqual(sizes, [1024, 4096, 4096, 4096])

    def test_crypt5_table_includes_salted_era_markers(self) -> None:
        # AC15: без этих двух маркеров salted-раскладка не расшифровывается.
        self.assertEqual(len(CRYPT5_KEYS), 36)
        self.assertIn("asajzqxt", CRYPT5_KEYS)
        self.assertIn("vdfzfoff", CRYPT5_KEYS)
        for marker in CRYPT5_KEYS:
            self.assertEqual(len(marker), 8, marker)


class HappDecryptTests(unittest.TestCase):
    def test_reference_vectors(self) -> None:
        for vector in VECTORS:
            with self.subTest(vector=vector["name"]):
                scheme, plaintext = decrypt_happ_link(vector["link"])
                self.assertTrue(vector["link"].lower().startswith(f"happ://{scheme}/"))
                self.assertTrue(plaintext)
                if vector["expected"] is not None:
                    self.assertEqual(plaintext, vector["expected"])
                else:
                    # Открытый текст этих векторов — произвольная строка, которую
                    # незачем держать в репозитории; закрепляем её хешем.
                    self.assertEqual(len(plaintext), vector["expected_len"])
                    self.assertEqual(
                        hashlib.sha256(plaintext.encode("utf-8")).hexdigest(),
                        vector["expected_sha256"],
                    )

    def test_both_crypt5_layouts_are_covered(self) -> None:
        names = {vector["name"] for vector in VECTORS}
        self.assertIn("crypt5-legacy-happwn-vector", names)
        self.assertIn("crypt5-salted-leeeet-vector", names)

    def test_is_happ_crypt_link(self) -> None:
        self.assertTrue(is_happ_crypt_link("happ://crypt5/abc"))
        self.assertTrue(is_happ_crypt_link("HAPP://CRYPT/abc"))
        self.assertFalse(is_happ_crypt_link("happ://add/https://example.com/sub"))
        self.assertFalse(is_happ_crypt_link("https://example.com/sub"))
        self.assertFalse(is_happ_crypt_link(""))


class HappDecryptFailureTests(unittest.TestCase):
    def _assert_domain_error(self, link: str) -> HappCryptError:
        with self.assertRaises(HappCryptError) as ctx:
            decrypt_happ_link(link)
        self.assertTrue(str(ctx.exception).strip())
        return ctx.exception

    def test_empty_payload(self) -> None:
        self._assert_domain_error("happ://crypt4/")

    def test_unknown_scheme(self) -> None:
        self._assert_domain_error("happ://add/https://example.com/sub")

    def test_broken_base64(self) -> None:
        self._assert_domain_error("happ://crypt4/!!!not-base64!!!")

    def test_length_not_multiple_of_key_size(self) -> None:
        self._assert_domain_error("happ://crypt4/" + base64.b64encode(b"short").decode())

    def test_unknown_crypt5_marker(self) -> None:
        error = self._assert_domain_error("happ://crypt5/" + "z" * 200)
        self.assertIn("маркер", str(error))

    def test_truncated_crypt5_body(self) -> None:
        salted = next(v for v in VECTORS if v["name"] == "crypt5-salted-leeeet-vector")
        payload = salted["link"].split("/", 3)[3]
        # Сохраняем маркер (первые и последние 4 символа), но рвём тело.
        broken = payload[:8] + payload[8:120] + payload[-8:]
        self._assert_domain_error("happ://crypt5/" + broken)


class HappSubscriptionSourceTests(unittest.TestCase):
    def test_crypt_link_resolves_to_subscription_url(self) -> None:
        vector = next(v for v in VECTORS if v["name"] == "crypt4-happwn-vector")
        url, hint = resolve_subscription_source(vector["link"])
        self.assertEqual(url, vector["expected"])
        self.assertEqual(hint, "happ")

    def test_crypt5_link_resolves_to_subscription_url(self) -> None:
        vector = next(v for v in VECTORS if v["name"] == "crypt5-salted-leeeet-vector")
        url, hint = resolve_subscription_source(vector["link"])
        self.assertEqual(url, vector["expected"])
        self.assertEqual(hint, "happ")

    def test_non_url_payload_reports_clear_error(self) -> None:
        # crypt2-вектор содержит произвольный текст, а не URL подписки.
        vector = next(v for v in VECTORS if v["name"] == "crypt2-sayoriroom")
        with self.assertRaises(SubscriptionFetchError) as ctx:
            resolve_subscription_source(vector["link"])
        self.assertIn("не содержит", str(ctx.exception).lower())

    def test_plain_add_link_still_works(self) -> None:
        url, hint = resolve_subscription_source("happ://add/https://example.com/sub")
        self.assertEqual(url, "https://example.com/sub")
        self.assertEqual(hint, "happ")


if __name__ == "__main__":
    unittest.main()
