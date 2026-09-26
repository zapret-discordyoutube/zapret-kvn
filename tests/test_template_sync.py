from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from build import stage_template_update_bundle
from xray_fluent.application.template_sync import merge_stock_sections, sync_packaged_templates


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

    def test_untouched_sections_follow_stock_while_edited_sections_are_kept(self):
        old_dns = {"servers": [{"type": "local", "tag": "proxy-dns"}], "final": "proxy-dns"}
        new_dns = {"servers": [{"type": "udp", "tag": "proxy-dns", "server": "1.1.1.1"}], "final": "proxy-dns"}
        old = {"log": {"level": "warn"}, "dns": old_dns, "route": {"final": "proxy"}}
        new = {"log": {"level": "warn"}, "dns": new_dns, "route": {"final": "proxy", "rules": []}}
        custom_route = {"final": "direct", "rules": [{"domain_suffix": ["example.org"], "outbound": "proxy"}]}
        _write_json(self.templates / "sing-box" / "default.json", old)
        _write_json(self.configs / "sing-box" / "default.json", {**old, "route": custom_route})
        _write_json(self.bundle / "sing-box" / "default.json", new)

        result = self._sync()

        active = json.loads((self.configs / "sing-box" / "default.json").read_text(encoding="utf-8"))
        self.assertEqual(active, {"log": {"level": "warn"}, "dns": new_dns, "route": custom_route})
        self.assertEqual(result.configs_updated, ("sing-box/default.json",))
        self.assertEqual(result.configs_preserved, ("sing-box/default.json",))
        self.assertFalse(self._sync().changed)

    def test_user_dns_is_never_rewritten_without_a_template_change(self):
        stock = {"dns": {"servers": [{"type": "local", "tag": "local"}]}, "route": {"final": "proxy"}}
        custom = {"dns": {"servers": [{"type": "tcp", "tag": "mine", "server": "9.9.9.9"}]}, "route": {"final": "proxy"}}
        _write_json(self.templates / "sing-box" / "default.json", stock)
        _write_json(self.bundle / "sing-box" / "default.json", stock)
        active = self.configs / "sing-box" / "default.json"
        _write_json(active, custom)
        other = self.configs / "sing-box" / "other.json"
        _write_json(other, custom)
        stamp = active.stat().st_mtime_ns

        self.assertFalse(self._sync().changed)

        self.assertEqual(json.loads(active.read_text(encoding="utf-8")), custom)
        self.assertEqual(json.loads(other.read_text(encoding="utf-8")), custom)
        self.assertEqual(stamp, active.stat().st_mtime_ns)

    def test_merge_keeps_user_removals_and_additions_and_adds_new_stock_sections(self):
        previous = {"log": {"level": "warn"}, "dns": {"final": "a"}, "ntp": {"enabled": False}}
        current = {"log": {"level": "info"}, "dns": {"final": "b"}, "experimental": {"cache_file": {"enabled": True}}}
        active = {"dns": {"final": "a"}, "ntp": {"enabled": False}, "inbounds": [{"type": "tun"}]}

        merged = merge_stock_sections(active, previous, current)

        # log was deleted by the user and stays deleted; dns and ntp were
        # untouched and follow the stock (ntp removed); inbounds is user-only.
        self.assertEqual(
            merged,
            {"dns": {"final": "b"}, "inbounds": [{"type": "tun"}], "experimental": {"cache_file": {"enabled": True}}},
        )

    def test_invalid_active_json_is_left_untouched_on_update(self):
        _write_json(self.templates / "sing-box" / "default.json", {"dns": {"final": "a"}})
        _write_json(self.bundle / "sing-box" / "default.json", {"dns": {"final": "b"}})
        active = self.configs / "sing-box" / "default.json"
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text('{"dns": unfinished', encoding="utf-8")

        result = self._sync()

        self.assertEqual(active.read_text(encoding="utf-8"), '{"dns": unfinished')
        self.assertEqual(result.configs_preserved, ("sing-box/default.json",))

if __name__ == "__main__":
    unittest.main()
