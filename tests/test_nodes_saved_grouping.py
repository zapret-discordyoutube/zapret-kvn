"""The saved grouping reaches the model when the view settings load (regression of 0e38c1e, caught by the win10 gate)."""

import unittest

from PyQt6.QtWidgets import QApplication

from xray_fluent.profiles.models import AppSettings
from xray_fluent.ui.nodes_page import NodesPage

_APP = QApplication.instance() or QApplication([])


class SavedGroupingTests(unittest.TestCase):
    def test_every_saved_mode_is_applied_to_the_model_and_shown_in_the_combo(self) -> None:
        # the combo is synced with its signals blocked: the model has to be told explicitly
        page = NodesPage()
        self.addCleanup(page.deleteLater)
        for saved in ("country", "country+server", "none", "source"):
            with self.subTest(saved=saved):
                page.apply_view_settings(AppSettings(nodes_group_by=saved))
                self.assertEqual(saved, page._table_model.group_mode())
                self.assertEqual(saved, page.group_by_combo.currentData())

    def test_a_broken_saved_mode_falls_back_to_the_default(self) -> None:
        page = NodesPage()
        self.addCleanup(page.deleteLater)
        page.apply_view_settings(AppSettings(nodes_group_by="country"))
        page.apply_view_settings(AppSettings(nodes_group_by="nonsense"))
        self.assertEqual("source", page._table_model.group_mode())


if __name__ == "__main__":
    unittest.main()
