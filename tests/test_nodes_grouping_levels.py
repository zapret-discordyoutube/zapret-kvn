"""The server list groups by levels the user picks (owner request 2026-11-27), on the owner's real server names."""

import json
import unittest
from pathlib import Path

from PyQt6.QtCore import QCoreApplication

from xray_fluent.profiles.models import Node
from xray_fluent.ui.group_levels_dialog import levels_title, mode_from_choices
from xray_fluent.ui.nodes_table_model import (
    GROUP_PRESET_LEVELS,
    GroupRow,
    NodesTableModel,
    group_levels,
    normalize_group_mode,
)

_APP = QCoreApplication.instance() or QCoreApplication([])
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "real_server_names.json"


def _real_nodes() -> list[Node]:
    rows = json.loads(FIXTURE.read_text(encoding="utf-8"))["nodes"]
    nodes = []
    for index, row in enumerate(rows):
        if row["group"] not in ("vpnbot-xray", "vpnbot-hysteria2"):
            continue
        nodes.append(Node(id=f"n{index}", name=row["name"], scheme=row["scheme"] or "vless", group=row["group"],
                          outbound={"type": row["scheme"] or "vless"}))
    return nodes


def _model(mode: str) -> NodesTableModel:
    model = NodesTableModel()
    model.set_nodes(_real_nodes())
    model.set_group_mode(mode)
    return model


def _rows(model: NodesTableModel) -> list:
    return [model.row_at(index) for index in range(model.rowCount())]


class GroupModeTests(unittest.TestCase):
    def test_presets_and_custom_levels(self) -> None:
        self.assertEqual(("country", "server", "type"), group_levels("country_server"))
        self.assertEqual(("type", "country"), group_levels("type+country"))
        self.assertEqual((), group_levels("none"))

    def test_a_bad_mode_falls_back_to_the_default(self) -> None:
        for bad in ("", "nonsense", "country+country", "country+server+type+source", "country+bogus"):
            with self.subTest(bad=bad):
                self.assertEqual("source", normalize_group_mode(bad))
        self.assertEqual("country+server", normalize_group_mode("country+server"))

    def test_the_dialog_turns_choices_into_a_mode(self) -> None:
        self.assertEqual("country+type", mode_from_choices(["country", "", "type"]))
        self.assertEqual("server", mode_from_choices(["server", "server", ""]))
        self.assertEqual("none", mode_from_choices(["", "", ""]))
        self.assertEqual("Страна › Сервер › Протокол", levels_title(("country", "server", "type")))


class NestedFoldersTests(unittest.TestCase):
    def test_the_levels_nest_and_every_key_is_under_the_last_folder(self) -> None:
        model = _model("country+server+type")
        rows = _rows(model)
        groups = [row for row in rows if isinstance(row, GroupRow)]
        self.assertEqual({0, 1, 2}, {group.depth for group in groups})
        leaves = [row for row in rows if not row.is_group]
        self.assertEqual(len(_real_nodes()), len(leaves))
        self.assertEqual({3}, {leaf.depth for leaf in leaves})
        # a folder's count is the number of keys below it
        for index, row in enumerate(rows):
            if not isinstance(row, GroupRow) or row.depth != 0:
                continue
            below = 0
            for later in rows[index + 1:]:
                if isinstance(later, GroupRow) and later.depth == 0:
                    break
                below += 0 if later.is_group else 1
            self.assertEqual(row.count, below, row.title)

    def test_country_folders_carry_the_country_name_and_flag_code(self) -> None:
        top = [row for row in _rows(_model("country")) if isinstance(row, GroupRow)]
        titles = {row.title: row.country for row in top}
        self.assertEqual("DE", titles.get("Германия"), titles)

    def test_a_server_is_one_folder_whatever_its_keys_are_called(self) -> None:
        model = _model("server")
        top = [row for row in _rows(model) if isinstance(row, GroupRow) and row.depth == 0]
        keys = len(_real_nodes())
        self.assertLess(len(top), keys // 4, (len(top), keys))

    def test_a_collapsed_folder_hides_everything_below_it(self) -> None:
        model = _model("country+server+type")
        first = next(row for row in _rows(model) if isinstance(row, GroupRow))
        before = model.rowCount()
        model.set_collapsed_groups({first.key})
        self.assertLess(model.rowCount(), before)
        hidden = next(node for node in _real_nodes() if model.collapsed_group_of(node.id) == first.key)
        self.assertIsNotNone(hidden)

    def test_the_same_server_name_under_two_countries_is_two_folders(self) -> None:
        nodes = [
            Node(id="a", name="🇩🇪 Alpha · VLESS", scheme="vless", outbound={"type": "vless"}),
            Node(id="b", name="🇳🇱 Alpha · VLESS", scheme="vless", outbound={"type": "vless"}),
        ]
        model = NodesTableModel()
        model.set_nodes(nodes)
        model.set_group_mode("country+server")
        keys = [row.key for row in _rows(model) if isinstance(row, GroupRow) and row.depth == 1]
        self.assertEqual(2, len(set(keys)), keys)

    def test_no_grouping_keeps_a_flat_list(self) -> None:
        rows = _rows(_model("none"))
        self.assertTrue(all(not row.is_group for row in rows))

    def test_every_preset_builds(self) -> None:
        for mode in GROUP_PRESET_LEVELS:
            with self.subTest(mode=mode):
                self.assertGreater(_model(mode).rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
