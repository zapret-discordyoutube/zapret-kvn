from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from build import stage_template_update_bundle
from xray_fluent.application.template_sync import sync_packaged_templates, sync_config_dns


def _write_json(path: Path, payload: object, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if compact:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")


class TemplateSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.bundle = self.root / "assets" / "template-update"
        self.templates = self.root / "data" / "templates"
        self.configs = self.root / "data" / "configs"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _sync(self):
        return sync_packaged_templates(
            bundle_dir=self.bundle,
            templates_dir=self.templates,
            configs_dir=self.configs,
        )

    def test_untouched_active_config_follows_updated_template_automatically(self) -> None:
        old = {"route": {"rules": [{"ip_is_private": True}]}}
        new = {"route": {"rules": [{"process_name": ["yandexmusic.exe"], "outbound": "direct"}]}}
        _write_json(self.templates / "sing-box" / "default.json", old)
        _write_json(self.configs / "sing-box" / "default.json", old, compact=True)
        _write_json(self.bundle / "sing-box" / "default.json", new)

        result = self._sync()

        self.assertEqual(
            json.loads((self.templates / "sing-box" / "default.json").read_text(encoding="utf-8")),
            new,
        )
        self.assertEqual(
            json.loads((self.configs / "sing-box" / "default.json").read_text(encoding="utf-8")),
            new,
        )
        self.assertEqual(result.templates_updated, ("sing-box/default.json",))
        self.assertEqual(result.configs_updated, ("sing-box/default.json",))
        self.assertEqual(result.configs_preserved, ())
        self.assertFalse(self._sync().changed)

    def test_user_edited_active_config_is_preserved(self) -> None:
        old = {"routing": {"rules": [{"outboundTag": "direct"}]}}
        new = {"routing": {"rules": [{"process": ["yandexmusic.exe"], "outboundTag": "direct"}]}}
        custom = {"routing": {"rules": [{"domain": ["full:example.org"], "outboundTag": "proxy"}]}}
        _write_json(self.templates / "xray" / "default.json", old)
        _write_json(self.configs / "xray" / "default.json", custom)
        _write_json(self.bundle / "xray" / "default.json", new)

        result = self._sync()

        self.assertEqual(
            json.loads((self.templates / "xray" / "default.json").read_text(encoding="utf-8")),
            new,
        )
        self.assertEqual(
            json.loads((self.configs / "xray" / "default.json").read_text(encoding="utf-8")),
            custom,
        )
        self.assertEqual(result.configs_updated, ())
        self.assertEqual(result.configs_preserved, ("xray/default.json",))

    def test_bundle_adds_new_templates_without_touching_custom_paths(self) -> None:
        bundled = {"route": {"final": "proxy"}}
        custom = {"route": {"final": "direct"}}
        _write_json(self.bundle / "sing-box" / "nested" / "new.json", bundled)
        _write_json(self.templates / "sing-box" / "custom.json", custom)
        _write_json(self.configs / "sing-box" / "custom.json", custom)

        result = self._sync()

        self.assertTrue((self.templates / "sing-box" / "nested" / "new.json").is_file())
        self.assertEqual(
            json.loads((self.templates / "sing-box" / "custom.json").read_text(encoding="utf-8")),
            custom,
        )
        self.assertEqual(
            json.loads((self.configs / "sing-box" / "custom.json").read_text(encoding="utf-8")),
            custom,
        )
        self.assertEqual(result.templates_updated, ("sing-box/nested/new.json",))

    def test_build_stages_fresh_template_bundle_outside_data(self) -> None:
        source = self.root / "source-templates"
        app_dir = self.root / "dist" / "ZapretKVN"
        _write_json(source / "sing-box" / "default.json", {"route": {"final": "proxy"}})
        stale = app_dir / "assets" / "template-update" / "stale.json"
        _write_json(stale, {"stale": True})

        destination = stage_template_update_bundle(source, app_dir)

        self.assertEqual(destination, app_dir / "assets" / "template-update")
        self.assertFalse(stale.exists())
        self.assertTrue((destination / "sing-box" / "default.json").is_file())

    def test_custom_routing_survives_automatic_dns_replacement_on_every_start(self):
        dns = {"servers": [{"type": "local", "tag": "proxy-dns"}], "final": "proxy-dns"}
        template = self.templates / "sing-box/default.json"
        active = self.configs / "sing-box/custom.json"
        _write_json(template, {"dns": dns})
        custom = {"dns": {"servers": [{"type": "tcp", "server": "8.8.8.8"}]},
                  "route": {"rules": [{"domain_suffix": ["example.org"], "outbound": "direct"}]},
                  "outbounds": [{"type": "direct", "tag": "proxy"}], "log": {"level": "debug"}}
        _write_json(active, custom)
        self.assertEqual(self._sync().configs_updated, ("sing-box/custom.json",))
        self.assertEqual(json.loads(active.read_text()), {**custom, "dns": dns})
        stamp = active.stat().st_mtime_ns
        self.assertFalse(self._sync().changed)
        self.assertEqual(stamp, active.stat().st_mtime_ns)
        _write_json(active, custom)
        self.assertTrue(self._sync().changed)
        self.assertEqual(json.loads(active.read_text())["dns"], dns)

    def test_dns_sync_does_not_destroy_invalid_editor_text(self):
        active = self.root / "invalid.json"
        template = self.root / "template.json"
        active.write_text('{"dns": unfinished')
        _write_json(template, {"dns": {"servers": ["localhost"]}})
        self.assertFalse(sync_config_dns(active, template))
        self.assertEqual(active.read_text(), '{"dns": unfinished')


if __name__ == "__main__":
    unittest.main()
