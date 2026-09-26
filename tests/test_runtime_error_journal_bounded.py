"""Журнал ошибок ядер: группировка «той же» ошибки и предел размера."""

from __future__ import annotations

import unittest

from xray_fluent.diagnostics.runtime_errors import MAX_JOURNAL_RECORDS, RuntimeErrorJournal, core_failure


class RuntimeErrorJournalBoundTests(unittest.TestCase):
    def test_same_error_with_new_time_id_and_port_is_one_record(self) -> None:
        journal = RuntimeErrorJournal()
        for second in range(50):
            journal.record(core_failure(
                "xray", "runtime",
                f"2026/09/26 16:{second:02d}:01 [Warning] [{1000 + second}] proxy: failed to dial 127.0.0.1:{40000 + second}",
            ))
        records = journal.snapshot()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].occurrences, 50)
        self.assertIn("40049", records[0].failure.message)  # показан последний исходный текст

    def test_distinct_errors_are_kept_apart(self) -> None:
        journal = RuntimeErrorJournal()
        journal.record(core_failure("xray", "runtime", "[Warning] connection reset"))
        journal.record(core_failure("xray", "runtime", "[Warning] certificate signed by unknown authority"))
        self.assertEqual(len(journal.snapshot()), 2)

    def test_journal_is_capped_and_evicts_least_recently_seen(self) -> None:
        journal = RuntimeErrorJournal(max_records=5)
        messages = [f"[Warning] distinct failure {chr(97 + i)}" for i in range(8)]
        journal.record(core_failure("xray", "runtime", messages[0]))
        for message in messages[1:]:
            journal.record(core_failure("xray", "runtime", message))
            journal.record(core_failure("xray", "runtime", messages[0]))  # «a» видим постоянно
        texts = [r.failure.message for r in journal.snapshot()]
        self.assertEqual(len(texts), 5)
        self.assertIn(messages[0], texts)

    def test_default_cap(self) -> None:
        journal = RuntimeErrorJournal()
        for i in range(MAX_JOURNAL_RECORDS + 50):
            journal.record(core_failure("sing-box", "runtime", f"ERROR unique failure kind {chr(65 + i % 26)}{'x' * (i // 26)}"))
        self.assertEqual(len(journal), MAX_JOURNAL_RECORDS)


if __name__ == "__main__":
    unittest.main()
