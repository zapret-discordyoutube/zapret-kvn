"""Every pytest run is a test run: nothing it does may reach the real report ingest.

On 2026-11-20 a targeted local run without ZAPRET_KVN_CLIENT_REPORTS=off sent six app errors of the dev tree to
production: a test built the real controller, whose reporter became the process-wide app-error sink, and later
tests in the same process hit the updater, storage and subscription failure paths. The switch is now set here for
every run (tests of the reporter itself pass ``enabled=True`` with a fake opener), and the sink is cleared after
each test so a controller of one test never receives another test's errors.
"""

from __future__ import annotations

import os

import pytest

os.environ["ZAPRET_KVN_CLIENT_REPORTS"] = "off"


@pytest.fixture(autouse=True)
def _no_app_error_sink_between_tests():
    yield
    from xray_fluent.client_reports import app_errors

    app_errors.set_sink(None)
    app_errors._early.clear()
