"""A subscription list carries NaiveProxy lines next to the other protocols (asked by the key service, 2026-11-27).

The service would send ``naive+https://`` lines in the usual Base64 URI list: the importer must take them with the rest, and
a bad line (an IP host) must be reported without taking the others down. The secrets below are placeholders of the right length.
"""

import base64
import unittest

from xray_fluent.importer.subscription_parser import parse_subscription_payload

NAIVE_ONE = (
    "naive+https://k-7f3a:Q2xpZW50U2VjcmV0MDEyMzQ1Njc4OQ@q417.ru1.example.com:443?insecure-concurrency=2"
    "#%F0%9F%87%B7%F0%9F%87%BA%20Alpha%20%C2%B7%20Naive%20%C2%B7%20V1"
)
NAIVE_TWO = "naive+https://k-7f3b:Q2xpZW50U2VjcmV0MDEyMzQ1Njc4QQ@q418.de1.example.com:443#%F0%9F%87%A9%F0%9F%87%AA%20Beta"
VLESS = "vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls&type=tcp#vless-one"
IP_HOST = "naive+https://a:Q2xpZW50U2VjcmV0MDEyMzQ1Njc4OQ@192.0.2.7:443#ip-host"


class NaiveSubscriptionListTests(unittest.TestCase):
    def _list(self) -> str:
        return "\n".join([VLESS, NAIVE_ONE, NAIVE_TWO]) + "\n"

    def test_plain_and_base64_lists_carry_the_naive_lines(self) -> None:
        text = self._list()
        for label, payload in (("plain", text), ("base64", base64.b64encode(text.encode()).decode())):
            with self.subTest(label=label):
                parsed = parse_subscription_payload(payload)
                self.assertEqual(["vless", "naive", "naive"], [node.scheme for node in parsed.nodes])
                self.assertEqual("naive", parsed.nodes[1].outbound["type"])

    def test_a_bad_naive_line_is_reported_and_the_others_still_import(self) -> None:
        payload = "\n".join([VLESS, NAIVE_ONE, IP_HOST]) + "\n"
        parsed = parse_subscription_payload(base64.b64encode(payload.encode()).decode())
        self.assertEqual(["vless", "naive"], [node.scheme for node in parsed.nodes])
        self.assertEqual(1, parsed.skipped, "the bad line is counted, not dropped silently")
        self.assertNotIn("Q2xpZW50U2VjcmV0MDEyMzQ1Njc4OQ", " ".join(parsed.warnings), "a secret must not reach the report")


if __name__ == "__main__":
    unittest.main()
