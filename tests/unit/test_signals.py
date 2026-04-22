"""Signal-handler snapshot/audit/mitigation helpers."""

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


class TestSnapshot:
    def test_returns_current_handlers(self) -> None:
        snap = snapshot_handlers()
        assert set(snap.keys()) <= set(_GO_MANAGED_SIGNALS)
        for sig in snap:
            assert isinstance(sig, int)

    def test_covers_core_signals(self) -> None:
        snap = snapshot_handlers()
        assert signal.SIGSEGV in snap
        assert signal.SIGPIPE in snap


class TestAudit:
    def test_no_displacement(self, caplog: pytest.LogCaptureFixture) -> None:
        pre = snapshot_handlers()
        with caplog.at_level(logging.WARNING):
            displaced = audit_after_load(pre, logging.getLogger("test.audit"))
        assert displaced == []

    def test_detects_displacement(self, caplog: pytest.LogCaptureFixture) -> None:
        original = signal.getsignal(signal.SIGPIPE)
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        baseline = signal.getsignal(signal.SIGPIPE)
        pre = {signal.SIGPIPE: baseline}
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
            with caplog.at_level(logging.WARNING):
                displaced = audit_after_load(pre, logging.getLogger("test.audit"))
            assert signal.SIGPIPE in displaced
            assert any("displaced" in rec.getMessage() for rec in caplog.records)
        finally:
            signal.signal(signal.SIGPIPE, original)

    def test_ignores_none_before(self) -> None:
        pre = {signal.SIGPIPE: None}
        displaced = audit_after_load(pre, logging.getLogger("test.audit"))
        assert displaced == []


class TestAsyncPreemptMitigation:
    def test_sets_godebug(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GODEBUG", raising=False)
        apply_asyncpreempt_mitigation()
        assert "asyncpreemptoff=1" in os.environ["GODEBUG"]

    def test_appends_without_duplicating(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GODEBUG", "madvdontneed=1")
        apply_asyncpreempt_mitigation()
        assert os.environ["GODEBUG"] == "madvdontneed=1,asyncpreemptoff=1"

    def test_idempotent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GODEBUG", "asyncpreemptoff=1")
        apply_asyncpreempt_mitigation()
        assert os.environ["GODEBUG"] == "asyncpreemptoff=1"
