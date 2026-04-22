"""`pycoraza._signals` audits handler displacement and mitigations."""

from __future__ import annotations

import logging
import os
import signal

import pytest

from pycoraza._signals import (
    _GO_MANAGED_SIGNALS,
    apply_asyncpreempt_mitigation,
    audit_after_load,
    snapshot_handlers,
)


pytestmark = pytest.mark.signals


class TestSnapshotHandlers:
    def test_contains_expected_signals(self) -> None:
        snap = snapshot_handlers()
        for sig in (signal.SIGSEGV, signal.SIGPIPE):
            assert sig in snap

    def test_values_reflect_current_handlers(self) -> None:
        snap = snapshot_handlers()
        for sig, value in snap.items():
            if value is None:
                continue
            assert value == signal.getsignal(sig)


class TestAudit:
    def test_no_displacement_no_log(self, caplog: pytest.LogCaptureFixture) -> None:
        pre = snapshot_handlers()
        logger = logging.getLogger("pycoraza.test.audit")
        with caplog.at_level(logging.WARNING, logger=logger.name):
            displaced = audit_after_load(pre, logger)
        assert displaced == []

    def test_displacement_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        original = signal.getsignal(signal.SIGPIPE)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        pre = {signal.SIGPIPE: signal.getsignal(signal.SIGPIPE)}
        logger = logging.getLogger("pycoraza.test.audit")
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            with caplog.at_level(logging.WARNING, logger=logger.name):
                displaced = audit_after_load(pre, logger)
        finally:
            signal.signal(signal.SIGPIPE, original)
        assert signal.SIGPIPE in displaced
        assert any("displaced" in rec.getMessage() for rec in caplog.records)

    def test_skips_unset_previous_handler(self) -> None:
        pre = {signal.SIGPIPE: None}
        displaced = audit_after_load(pre, logging.getLogger("pycoraza.test.audit"))
        assert signal.SIGPIPE not in displaced


class TestAsyncPreemptMitigation:
    def test_adds_to_empty_godebug(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GODEBUG", raising=False)
        apply_asyncpreempt_mitigation()
        assert os.environ["GODEBUG"] == "asyncpreemptoff=1"

    def test_appends_to_existing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GODEBUG", "gctrace=1")
        apply_asyncpreempt_mitigation()
        assert "asyncpreemptoff=1" in os.environ["GODEBUG"]
        assert "gctrace=1" in os.environ["GODEBUG"]

    def test_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GODEBUG", "asyncpreemptoff=1,other=1")
        apply_asyncpreempt_mitigation()
        assert os.environ["GODEBUG"] == "asyncpreemptoff=1,other=1"


class TestGoManagedSet:
    def test_non_empty(self) -> None:
        assert len(_GO_MANAGED_SIGNALS) >= 5
