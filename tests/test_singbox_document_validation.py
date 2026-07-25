from pathlib import Path
import unittest

from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document


class SingboxDocumentValidationTests(unittest.TestCase):
    def test_array_root_explains_how_to_fix_the_config(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"example\.json: конфиг sing-box начинается с массива \[…\].*"
            r"объекта \{\.\.\.\}.*Уберите внешние квадратные скобки",
        ):
            parse_singbox_document(Path("example.json"), "[{}]")

    def test_string_root_explains_how_to_fix_the_config(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"example\.json: весь конфиг sing-box распознан как строка.*"
            r"объектом \{\.\.\.\}.*Уберите внешние кавычки и экранирование",
        ):
            parse_singbox_document(Path("example.json"), '"{\\"log\\": {}}"')

    def test_null_root_requests_a_complete_config_object(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"example\.json: вместо полного объекта \{\.\.\.\} указано null.*"
            r"Вставьте конфиг sing-box целиком",
        ):
            parse_singbox_document(Path("example.json"), "null")

    def test_scalar_root_names_its_type(self) -> None:
        for text, type_name in (("true", "логическое значение"), ("42", "число")):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, type_name):
                parse_singbox_document(Path("example.json"), text)

    def test_object_root_is_accepted(self) -> None:
        document = parse_singbox_document(Path("example.json"), "{}")

        self.assertEqual(document.payload, {})


if __name__ == "__main__":
    unittest.main()
