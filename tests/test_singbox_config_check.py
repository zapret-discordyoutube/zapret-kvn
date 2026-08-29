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

        with patch(
            "xray_fluent.subprocess_utils.run_text_pumped",
            return_value=completed,
        ) as run_mock:
            self.assertEqual(check_config(exe, config), (True, ""))

        self.assertEqual(
            run_mock.call_args.args[0],
            [str(exe), "check", "-D", str(exe.parent), "-c", str(config)],
        )


if __name__ == "__main__":
    unittest.main()
