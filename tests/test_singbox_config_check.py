from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from xray_fluent.engines.singbox.config_check import check_config


class SingboxConfigCheckTests(unittest.TestCase):
    def test_check_uses_core_as_working_directory_for_local_rule_sets(self) -> None:
        exe = Path("C:/ZapretKVN/core/sing-box.exe")
        config = Path("C:/ZapretKVN/data/runtime/singbox_config.json")
        completed = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

        # check_config выполняется в worker-пуле: без прокачки Qt-событий.
        with patch(
            "xray_fluent.platform.windows.subprocess_utils.run_text",
            return_value=completed,
        ) as run_mock, patch(
            "xray_fluent.platform.windows.subprocess_utils.run_text_pumped",
        ) as pumped_mock:
            self.assertEqual(check_config(exe, config), (True, ""))

        self.assertEqual(
            run_mock.call_args.args[0],
            [str(exe), "check", "-D", str(exe.parent), "-c", str(config)],
        )
        pumped_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
