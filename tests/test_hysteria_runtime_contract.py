from __future__ import annotations

import json
from pathlib import Path
import unittest

from xray_fluent.engines.hysteria.runtime_contract import (
    AUTOMATIC_SWITCH_FAILURES,
    SECURITY_FAILURES,
    HysteriaFailureCode,
    HysteriaRuntimeState,
    HysteriaTransitionContract,
    choose_compatible_fallback,
    classify_hysteria_failure,
    classify_hysteria_uri,
    node_is_maintenance,
)
from xray_fluent.importer.link_parser import parse_single


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "hysteria_golden_vectors.json"


class HysteriaGoldenVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["vectors"]

    def test_windows_capability_matches_all_golden_vectors(self) -> None:
        for vector in self.vectors:
            with self.subTest(vector=vector["id"]):
                expected = vector["expected"]
                result = classify_hysteria_uri(vector["uri"], platform="windows")
                requirements = set(expected["requirements"])
                if expected["valid"]:
                    requirements.add("process_bypass_required")
                self.assertEqual(result.valid, expected["valid"])
                self.assertEqual(result.obfs_kind, expected["obfs_kind"])
                self.assertEqual(result.tls_kind, expected["tls_kind"])
                self.assertEqual(result.endpoint_kind, expected["endpoint_kind"])
                self.assertEqual(result.runtime_requirements, frozenset(requirements))
                self.assertEqual(result.execution_kind.value, expected["windows_execution"])
                self.assertEqual(result.switch_kind.value, expected["windows_switch"])
                self.assertEqual(
                    result.failure_code.value if result.failure_code else None,
                    expected.get("failure"),
                )

    def test_valid_vectors_preserve_raw_uri_and_security_fields(self) -> None:
        for vector in self.vectors:
            if not vector["expected"]["valid"]:
                continue
            with self.subTest(vector=vector["id"]):
                node = parse_single(vector["uri"])
                self.assertEqual(node.link, vector["uri"])
                self.assertEqual(
                    bool(node.outbound.get("certificate_sha256")),
                    vector["expected"]["tls_kind"] == "pinned",
                )
                if vector["expected"]["obfs_kind"] != "none":
                    self.assertEqual(
                        node.outbound["obfs"]["type"],
                        vector["expected"]["obfs_kind"],
                    )

    def test_maintenance_metadata_is_excluded_without_mutating_capability(self) -> None:
        vector = next(item for item in self.vectors if item["id"] == "maintenance_metadata")
        node = parse_single(vector["uri"])
        node.tags = list(vector["metadata"]["tags"])
        self.assertTrue(node_is_maintenance(node))
        self.assertTrue(classify_hysteria_uri(node.link).valid)


class HysteriaFailureAndTransitionTests(unittest.TestCase):
    def test_failure_taxonomy_preserves_original_failure(self) -> None:
        cases = {
            "no recent network activity": HysteriaFailureCode.TARGET_NETWORK_TIMEOUT,
            "connect: connection refused": HysteriaFailureCode.TARGET_CONNECTION_REFUSED,
            "tls: internal error": HysteriaFailureCode.TARGET_TLS_INTERNAL,
            "certificate signed by unknown authority": HysteriaFailureCode.TARGET_TLS_UNKNOWN_AUTHORITY,
            "certificate pin mismatch": HysteriaFailureCode.TARGET_PIN_MISMATCH,
            "connect error: CRYPTO_ERROR 0x12a (local): no certificate matches the pinned hash": HysteriaFailureCode.TARGET_PIN_MISMATCH,
            "tls: pinned certificate did not match": HysteriaFailureCode.TARGET_PIN_MISMATCH,
            "authentication failed": HysteriaFailureCode.TARGET_AUTH_REJECTED,
            "obfs rejected": HysteriaFailureCode.TARGET_OBFS_REJECTED,
            "address already in use": HysteriaFailureCode.LOCAL_BIND_COLLISION,
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(classify_hysteria_failure(message), expected)
        self.assertEqual(
            classify_hysteria_failure("exit status 62097", process_exited=True),
            HysteriaFailureCode.LOCAL_PROCESS_EXITED,
        )

    def test_only_operational_failures_trigger_automatic_switch(self) -> None:
        self.assertIn(HysteriaFailureCode.TARGET_NETWORK_TIMEOUT, AUTOMATIC_SWITCH_FAILURES)
        self.assertIn(HysteriaFailureCode.LOCAL_PROCESS_EXITED, AUTOMATIC_SWITCH_FAILURES)
        self.assertTrue(SECURITY_FAILURES.isdisjoint(AUTOMATIC_SWITCH_FAILURES))

    def test_ready_replacement_commit_and_stale_exit_fence(self) -> None:
        contract = HysteriaTransitionContract()
        contract.begin(12, "old", "official_hysteria_sidecar")
        for state in (
            HysteriaRuntimeState.STARTING_FRONT,
            HysteriaRuntimeState.STARTING_SIDECAR,
            HysteriaRuntimeState.WAITING_RELAY,
            HysteriaRuntimeState.READY,
            HysteriaRuntimeState.SWITCH_REQUESTED,
            HysteriaRuntimeState.PREPARING_REPLACEMENT,
            HysteriaRuntimeState.REPLACEMENT_READY,
            HysteriaRuntimeState.COMMITTING_SWITCH,
            HysteriaRuntimeState.STOPPING_OLD,
            HysteriaRuntimeState.READY,
        ):
            self.assertTrue(contract.advance(state, generation=12))
        self.assertFalse(contract.advance(HysteriaRuntimeState.FAILED, generation=11))
        self.assertEqual(contract.session.state, HysteriaRuntimeState.READY)
        self.assertEqual(
            contract.session.last_failure_code,
            HysteriaFailureCode.TRANSITION_STALE_GENERATION,
        )

    def test_one_fallback_excludes_current_maintenance_and_cooldown(self) -> None:
        current = parse_single("hy2://auth@current.example:443/")
        maintenance = parse_single("hy2://auth@maintenance.example:443/")
        maintenance.tags = ["maintenance"]
        cooling = parse_single("hy2://auth@cooldown.example:443/")
        selected = parse_single("hy2://auth@selected.example:443/")
        result = choose_compatible_fallback(
            [current, maintenance, cooling, selected],
            failed_node_id=current.id,
            cooldown_until={cooling.id: 500.0},
            capability=lambda node: classify_hysteria_uri(node.link),
            now=100.0,
        )
        self.assertIs(result, selected)

    def test_no_compatible_fallback_does_not_retry_current(self) -> None:
        current = parse_single("hy2://auth@current.example:443/")
        self.assertIsNone(
            choose_compatible_fallback(
                [current],
                failed_node_id=current.id,
                cooldown_until={},
                capability=lambda node: classify_hysteria_uri(node.link),
            )
        )


if __name__ == "__main__":
    unittest.main()
