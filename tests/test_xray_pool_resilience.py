from __future__ import annotations

import copy
import unittest
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock, patch

from PyQt6.QtCore import QCoreApplication

from xray_fluent.application.async_steps import TransitionProfile, TransitionRunner, sleep_ms
from xray_fluent.application.controller import AppController
from xray_fluent.application.outbound_pool_service import XRAY_OUTBOUND_PREFIX, build_xray_outbound_pool
from xray_fluent.diagnostics.runtime_errors import RepeatedNoticeFilter, is_deprecation_notice
from xray_fluent.engines.singbox.runtime_planner import parse_singbox_document, plan_singbox_proxy_runtime
from xray_fluent.engines.xray.manager import XrayManager
from xray_fluent.engines.xray_outbound_compat import (
    failed_outbound_tag,
    normalize_xray_outbound,
    xray_outbound_incompatibility,
)
from xray_fluent.importer.link_parser import parse_single

_APP = QCoreApplication.instance() or QCoreApplication([])

ROOT = Path(__file__).resolve().parents[1]
SINGBOX_TEMPLATE = ROOT / "data" / "templates" / "sing-box" / "default.json"

_VLESS = "vless://11111111-1111-1111-1111-111111111111@{host}:443?{query}#{name}"


def _tcp(host: str = "one.example", name: str = "one"):
    return parse_single(_VLESS.format(host=host, query="type=tcp&security=tls&sni=" + host, name=name))


def _kcp(host: str, name: str, header: str = "none"):
    return parse_single(_VLESS.format(host=host, query=f"type=kcp&security=none&headerType={header}", name=name))


class OutboundCompatTests(unittest.TestCase):
    def test_parser_does_not_write_empty_kcp_header(self) -> None:
        node = _kcp("kcp.example", "kcp")
        self.assertEqual(node.outbound["streamSettings"]["kcpSettings"], {})
        self.assertEqual(xray_outbound_incompatibility(node.outbound), "")

    def test_parser_keeps_real_masking_header_and_marks_it_incompatible(self) -> None:
        node = _kcp("kcp.example", "kcp", header="srtp")
        self.assertEqual(node.outbound["streamSettings"]["kcpSettings"]["header"], {"type": "srtp"})
        self.assertIn("srtp", xray_outbound_incompatibility(node.outbound))

    def test_saved_node_with_header_none_is_normalized_without_loss(self) -> None:
        outbound = _kcp("kcp.example", "kcp").outbound
        outbound["streamSettings"]["kcpSettings"]["header"] = {"type": "none"}

        self.assertEqual(xray_outbound_incompatibility(outbound), "")
        normalized = normalize_xray_outbound(copy.deepcopy(outbound))
        self.assertNotIn("header", normalized["streamSettings"]["kcpSettings"])
        # Сохранённый узел не тронут: нормализация работает на копии.
        self.assertIn("header", outbound["streamSettings"]["kcpSettings"])

    def test_seed_is_incompatible(self) -> None:
        outbound = _kcp("kcp.example", "kcp").outbound
        outbound["streamSettings"]["kcpSettings"]["seed"] = "secret"
        self.assertIn("seed", xray_outbound_incompatibility(outbound))

    def test_other_transports_are_untouched(self) -> None:
        outbound = _tcp().outbound
        before = copy.deepcopy(outbound)
        self.assertEqual(xray_outbound_incompatibility(outbound), "")
        self.assertEqual(normalize_xray_outbound(outbound), before)

    def test_failed_outbound_tag_is_read_from_core_output(self) -> None:
        lines = [
            "2026/10/18 13:28:06 [Warning] common/errors: The feature gRPC transport is deprecated",
            "Failed to start: main: failed to load config files: [x.json] > infra/conf: failed to build "
            f"outbound config with tag {XRAY_OUTBOUND_PREFIX}1c2407ea4cdc7dca9f3b > infra/conf: failed to build stream settings",
        ]
        self.assertEqual(
            failed_outbound_tag(lines, prefix=XRAY_OUTBOUND_PREFIX),
            f"{XRAY_OUTBOUND_PREFIX}1c2407ea4cdc7dca9f3b",
        )
        self.assertEqual(failed_outbound_tag(lines, prefix="other_"), "")
        self.assertEqual(failed_outbound_tag([], prefix=""), "")


class PoolAdmissionTests(unittest.TestCase):
    def test_pool_excludes_nodes_the_core_cannot_build(self) -> None:
        good = _tcp()
        masked = _kcp("masked.example", "masked", header="srtp")
        plain_kcp = _kcp("plain.example", "plain")
        plain_kcp.outbound["streamSettings"]["kcpSettings"]["header"] = {"type": "none"}

        pool = build_xray_outbound_pool([good, masked, plain_kcp])

        self.assertTrue(pool.contains(good.id))
        self.assertTrue(pool.contains(plain_kcp.id))
        self.assertFalse(pool.contains(masked.id))
        self.assertIn("srtp", pool.excluded[masked.id])
        kcp_outbound = next(item for item in pool.outbounds() if item["tag"] == pool.tag_for(plain_kcp.id))
        self.assertNotIn("header", kcp_outbound["streamSettings"]["kcpSettings"])

    def test_quarantined_node_stays_out_until_it_is_released(self) -> None:
        one, two = _tcp("one.example", "one"), _tcp("two.example", "two")
        pool = build_xray_outbound_pool([one, two], quarantine={two.id: "ядро отвергло"})
        self.assertEqual(list(pool.tags), [one.id])
        self.assertEqual(pool.excluded, {two.id: "ядро отвергло"})

    def test_hybrid_plan_leaves_rejected_nodes_out_and_names_the_reason(self) -> None:
        good = _tcp()
        masked = _kcp("masked.example", "masked", header="srtp")
        document = parse_singbox_document(SINGBOX_TEMPLATE, SINGBOX_TEMPLATE.read_text(encoding="utf-8"))

        plan = plan_singbox_proxy_runtime(document, good, pool_nodes=[good, masked])
        tags = [item["tag"] for item in plan.xray_sidecar.config["outbounds"]]
        self.assertIn(plan.selector_tags[good.id], tags)
        self.assertNotIn(masked.id, plan.selector_tags)
        self.assertEqual(len([tag for tag in tags if tag.startswith(XRAY_OUTBOUND_PREFIX)]), 1)

        with self.assertRaisesRegex(ValueError, "srtp"):
            plan_singbox_proxy_runtime(document, masked, pool_nodes=[good, masked])


def _controller_stub(nodes):
    stub = SimpleNamespace(
        state=SimpleNamespace(nodes=nodes),
        _xray_pool_quarantine={},
        _xray_pool_quarantine_version=0,
        _log=Mock(),
        status=SimpleNamespace(emit=Mock()),
        _invalidate_xray_outbound_pool_cache=Mock(),
        _invalidate_plan_facts_cache=Mock(),
    )
    for name in ("_xray_pool_quarantine_reasons", "_pool_candidate_nodes", "_quarantine_pruned_xray_outbounds"):
        setattr(stub, name, MethodType(getattr(AppController, name), stub))
    return stub


class QuarantineTests(unittest.TestCase):
    def _plan(self, nodes, selected):
        pool = build_xray_outbound_pool(nodes)
        return SimpleNamespace(
            xray_sidecar=SimpleNamespace(outbound_pool_tags=dict(pool.tags)),
            selector_tags=None,
            selected_outbound_tag=pool.tag_for(selected.id),
        ), pool

    def test_rejected_node_is_quarantined_and_removed_from_plan(self) -> None:
        one, two = _tcp("one.example", "one"), _tcp("two.example", "two")
        stub = _controller_stub([one, two])
        plan, pool = self._plan([one, two], one)
        plan.selector_tags = plan.xray_sidecar.outbound_pool_tags

        message = stub._quarantine_pruned_xray_outbounds(plan, [pool.tag_for(two.id)])

        self.assertEqual(message, "")
        self.assertEqual(list(plan.selector_tags), [one.id])
        self.assertEqual(stub._xray_pool_quarantine_reasons().keys(), {two.id})
        self.assertEqual(stub._pool_candidate_nodes(one), [one])
        stub.status.emit.assert_called_once()
        stub._invalidate_xray_outbound_pool_cache.assert_called_once()

    def test_rejected_selected_node_is_reported_and_stays_a_candidate(self) -> None:
        one, two = _tcp("one.example", "one"), _tcp("two.example", "two")
        stub = _controller_stub([one, two])
        plan, pool = self._plan([one, two], one)

        message = stub._quarantine_pruned_xray_outbounds(plan, [pool.tag_for(one.id)])

        self.assertIn("one", message)
        self.assertEqual(stub._pool_candidate_nodes(one), [one, two])  # выбранный остаётся, чтобы назвать причину
        self.assertEqual(stub._pool_candidate_nodes(two), [two])
        stub.status.emit.assert_not_called()

    def test_quiet_mode_does_not_toast(self) -> None:
        one, two = _tcp("one.example", "one"), _tcp("two.example", "two")
        stub = _controller_stub([one, two])
        plan, pool = self._plan([one, two], one)
        stub._quarantine_pruned_xray_outbounds(plan, [pool.tag_for(two.id)], notify=False)
        stub.status.emit.assert_not_called()

    def test_replaced_outbound_releases_the_node(self) -> None:
        one, two = _tcp("one.example", "one"), _tcp("two.example", "two")
        stub = _controller_stub([one, two])
        plan, pool = self._plan([one, two], one)
        stub._quarantine_pruned_xray_outbounds(plan, [pool.tag_for(two.id)])
        version = stub._xray_pool_quarantine_version

        two.outbound = copy.deepcopy(two.outbound)  # подписка пересобрала узел

        self.assertEqual(stub._xray_pool_quarantine_reasons(), {})
        self.assertEqual(stub._pool_candidate_nodes(one), [one, two])
        self.assertGreater(stub._xray_pool_quarantine_version, version)


class ManagerSelfHealTests(unittest.TestCase):
    def test_prune_removes_only_the_named_outbound(self) -> None:
        config = {"outbounds": [{"tag": "__app_proxy_a"}, {"tag": "__app_proxy_b"}, {"tag": "direct"}]}
        self.assertTrue(XrayManager._prune_outbound(config, "__app_proxy_b"))
        self.assertEqual([item["tag"] for item in config["outbounds"]], ["__app_proxy_a", "direct"])
        self.assertFalse(XrayManager._prune_outbound(config, "__app_proxy_missing"))

    def test_startup_failure_is_held_while_a_retry_is_possible(self) -> None:
        manager = XrayManager()
        errors: list[str] = []
        manager.error.connect(errors.append)
        manager._hold_startup_failure = True

        manager._report_startup_failure("первая попытка")
        manager._report_startup_failure("дубль")
        self.assertEqual(errors, [])

        self.assertFalse(manager._startup_failed())
        self.assertEqual(errors, ["первая попытка"])
        manager._startup_failure_reported = False
        manager._report_startup_failure("после запуска")
        self.assertEqual(errors, ["первая попытка", "после запуска"])


class RepeatedNoticeTests(unittest.TestCase):
    LINE = (
        "2026/10/18 13:28:06.221198 [Warning] common/errors: The feature gRPC transport "
        "(with unnecessary costs, etc.) is deprecated, not recommended for using."
    )

    def test_deprecation_notice_is_recognised_but_real_warnings_are_not(self) -> None:
        self.assertTrue(is_deprecation_notice(self.LINE))
        self.assertFalse(is_deprecation_notice("2026/10/18 13:28:06 [Warning] app/dns: failed to lookup"))
        self.assertFalse(is_deprecation_notice("2026/10/18 13:28:06 [Error] The feature x is gone"))

    def test_first_line_passes_repeats_are_counted(self) -> None:
        notices = RepeatedNoticeFilter()
        later = self.LINE.replace("13:28:06.221198", "13:28:07.000001")
        self.assertTrue(notices.first_time("xray", self.LINE))
        self.assertFalse(notices.first_time("xray", later))
        self.assertFalse(notices.first_time("xray", later))
        self.assertTrue(notices.first_time("sing-box", self.LINE))

        summary = notices.drain_summary("xray")
        self.assertEqual(len(summary), 1)
        self.assertIn("скрыто повторов: 2", summary[0])
        self.assertNotIn("13:28", summary[0])
        self.assertEqual(notices.drain_summary("xray"), [])
        self.assertTrue(notices.first_time("xray", self.LINE))


class TransitionProfileTests(unittest.TestCase):
    def test_slow_slice_is_reported_with_its_place(self) -> None:
        import time

        profile = TransitionProfile()
        profile.add_gui(time.perf_counter() - 0.5, "start_steps:140→start_steps:150")
        profile.add_gui(time.perf_counter(), "fast:1→fast:2")
        self.assertEqual([where for where, _ms in profile.slow_slices], ["start_steps:140→start_steps:150"])
        self.assertIn("медленно в GUI: start_steps:140→start_steps:150=5", profile.summary())

    def test_runner_names_the_blocking_generator_line(self) -> None:
        import time

        def steps():
            yield sleep_ms(0)
            time.sleep(0.15)  # блокирующий кусок на GUI-потоке
            yield sleep_ms(0)

        runner = TransitionRunner(steps())
        runner.start()
        deadline = time.monotonic() + 5
        while not runner.done and time.monotonic() < deadline:
            _APP.processEvents()
        self.assertTrue(runner.profile.slow_slices)
        self.assertIn("steps:", runner.profile.slow_slices[0][0])


if __name__ == "__main__":
    unittest.main()
