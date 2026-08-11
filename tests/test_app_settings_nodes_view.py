import unittest

from xray_fluent.models import AppSettings


class AppSettingsNodesViewTests(unittest.TestCase):
    def test_defaults_are_manual_sort_and_empty_filters(self) -> None:
        settings = AppSettings()
        self.assertEqual(settings.nodes_sort_key, "manual")
        self.assertFalse(settings.nodes_sort_desc)
        self.assertEqual(settings.nodes_group_filter, "")
        self.assertEqual(settings.nodes_tag_filter, "")
        self.assertEqual(settings.nodes_source_filter, "")
        self.assertEqual(settings.nodes_visible_columns, [])

    def test_legacy_dict_without_view_keys_yields_defaults(self) -> None:
        legacy = AppSettings().to_dict()
        for key in (
            "nodes_sort_key",
            "nodes_sort_desc",
            "nodes_group_filter",
            "nodes_tag_filter",
            "nodes_source_filter",
            "nodes_visible_columns",
        ):
            legacy.pop(key, None)

        restored = AppSettings.from_dict(legacy)
        self.assertEqual(restored.nodes_sort_key, "manual")
        self.assertFalse(restored.nodes_sort_desc)
        self.assertEqual(restored.nodes_group_filter, "")
        self.assertEqual(restored.nodes_tag_filter, "")
        self.assertEqual(restored.nodes_source_filter, "")
        self.assertEqual(restored.nodes_visible_columns, [])

    def test_round_trip_preserves_view_preferences(self) -> None:
        settings = AppSettings(
            nodes_sort_key="ping",
            nodes_sort_desc=True,
            nodes_group_filter="EU",
            nodes_tag_filter="fast",
            nodes_source_filter="Provider",
            nodes_visible_columns=["name", "address", "ping", "speed", "source"],
        )
        restored = AppSettings.from_dict(settings.to_dict())
        self.assertEqual(restored.nodes_sort_key, "ping")
        self.assertTrue(restored.nodes_sort_desc)
        self.assertEqual(restored.nodes_group_filter, "EU")
        self.assertEqual(restored.nodes_tag_filter, "fast")
        self.assertEqual(restored.nodes_source_filter, "Provider")
        self.assertEqual(
            restored.nodes_visible_columns,
            ["name", "address", "ping", "speed", "source"],
        )

    def test_visible_columns_lists_are_independent_between_instances(self) -> None:
        first = AppSettings()
        second = AppSettings()
        first.nodes_visible_columns.append("ping")
        self.assertEqual(second.nodes_visible_columns, [])


if __name__ == "__main__":
    unittest.main()
