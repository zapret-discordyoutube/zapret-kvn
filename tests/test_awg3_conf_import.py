"""Импорт AWG 3.0 .conf: перенос всех полей третьего поколения в sing-box JSON.

VPnBot выдаёт .conf с HeaderProtectionKey/ContentPaddingAddition (и до пяти
необязательных таймеров). Без переноса этих строк в объект ``amnezia``
профиль формально валиден, но сервер AWG 3.0 не отвечает на рукопожатие.
Схема ядра sing-box extended 2.6.x: snake_case, Range = число или "A-B".
"""
import unittest

from xray_fluent.link_parser import (
    LinkParseError,
    parse_links_text,
    validate_node_outbound,
)


HPK = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY="  # base64 от 32 байт

FIXTURE_AWG3_CONF = f"""[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.9.1.5/32
Jc = 4
Jmin = 64
Jmax = 160
S1 = 44
S2 = 63
H1 = 431245120-431245220
H2 = 1187345001
I1 = <b 0xf6ab5b>
HeaderProtectionKey = {HPK}
ContentPaddingAddition = 0-96
RekeyAfterTime = 120-180
RekeyTimeout = 5
RejectAfterTime = 600
KeepaliveTimeout = 25
MaxHandshakeAttempts = 20-30

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.20:44553
AllowedIPs = 0.0.0.0/0
"""


def _conf(**overrides: str) -> str:
    lines = FIXTURE_AWG3_CONF.splitlines()
    result = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in overrides:
            value = overrides.pop(key)
            if value is not None:
                result.append(f"{key} = {value}")
            continue
        result.append(line)
    return "\n".join(result) + "\n"


class TestAwg3ConfImport(unittest.TestCase):
    def test_generation3_fields_reach_amnezia_object(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_AWG3_CONF)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node.scheme, "awg")
        amnezia = node.outbound["amnezia"]
        self.assertEqual(amnezia["header_protection_key"], HPK)
        self.assertEqual(amnezia["content_padding_addition"], "0-96")
        self.assertEqual(amnezia["rekey_after_time"], "120-180")
        self.assertEqual(amnezia["rekey_timeout"], 5)
        self.assertIsInstance(amnezia["rekey_timeout"], int)
        self.assertEqual(amnezia["reject_after_time"], 600)
        self.assertEqual(amnezia["keepalive_timeout"], 25)
        self.assertEqual(amnezia["max_handshake_attempts"], "20-30")
        # Прежние поля второго поколения не сломаны.
        self.assertEqual(amnezia["jc"], 4)
        self.assertEqual(amnezia["h1"], "431245120-431245220")
        # Конфиг проходит финальную валидацию узла.
        self.assertIsNone(validate_node_outbound(node))

    def test_second_generation_conf_has_no_generation3_keys(self) -> None:
        conf = _conf(
            HeaderProtectionKey=None,
            ContentPaddingAddition=None,
            RekeyAfterTime=None,
            RekeyTimeout=None,
            RejectAfterTime=None,
            KeepaliveTimeout=None,
            MaxHandshakeAttempts=None,
        )
        nodes, errors = parse_links_text(conf)
        self.assertEqual(errors, [])
        amnezia = nodes[0].outbound["amnezia"]
        for key in (
            "header_protection_key",
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
        ):
            self.assertNotIn(key, amnezia)

    def test_header_protection_key_must_be_base64_of_32_bytes(self) -> None:
        for bad in ("not-base64!!", "QUJD", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZn"):
            nodes, errors = parse_links_text(_conf(HeaderProtectionKey=bad))
            self.assertEqual(nodes, [], bad)
            self.assertEqual(len(errors), 1, bad)
            self.assertIn("HeaderProtectionKey", errors[0])

    def test_range_fields_are_strictly_validated(self) -> None:
        for field, bad in (
            ("ContentPaddingAddition", "96-0"),
            ("ContentPaddingAddition", "abc"),
            ("RekeyAfterTime", "1-2-3"),
            ("MaxHandshakeAttempts", "4294967296"),
            ("KeepaliveTimeout", "10-4294967296"),
        ):
            nodes, errors = parse_links_text(_conf(**{field: bad}))
            self.assertEqual(nodes, [], f"{field}={bad}")
            self.assertEqual(len(errors), 1, f"{field}={bad}")
            self.assertIn(field, errors[0])

    def test_json_validator_checks_generation3_values(self) -> None:
        nodes, errors = parse_links_text(FIXTURE_AWG3_CONF)
        self.assertEqual(errors, [])
        node = nodes[0]
        node.outbound["amnezia"]["header_protection_key"] = "QUJD"
        message = validate_node_outbound(node)
        self.assertIsNotNone(message)
        self.assertIn("HeaderProtectionKey", message)
        node.outbound["amnezia"]["header_protection_key"] = HPK
        node.outbound["amnezia"]["content_padding_addition"] = "96-0"
        message = validate_node_outbound(node)
        self.assertIsNotNone(message)
        self.assertIn("content_padding_addition", message)


if __name__ == "__main__":
    unittest.main()
