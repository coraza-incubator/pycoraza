"""`Transaction` lifecycle + fused `process_request_bundle`/`process_response`."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

from pycoraza import (
    CorazaError,
    ProcessMode,
    RequestInfo,
    ResponseInfo,
    WAFConfig,
    create_waf,
)


def _make_waf(mode: ProcessMode = ProcessMode.BLOCK):
    return create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))


def _req(
    url: str = "/",
    method: str = "GET",
    body: bytes | None = None,
    headers: tuple[tuple[str, str], ...] = (),
) -> RequestInfo:
    return RequestInfo(
        method=method,
        url=url,
        headers=headers,
        remote_addr="127.0.0.1",
        remote_port=54321,
        server_port=8080,
    )


class TestLifecycle:
    def test_close_idempotent(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        tx.close()
        waf.close()

    def test_handle_after_close_raises(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        with pytest.raises(CorazaError):
            _ = tx.handle
        waf.close()

    def test_context_manager_logs_then_closes(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        with waf.new_transaction() as tx:
            tx.process_connection("1.1.1.1", 10)
        logs = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in logs
        assert "free_transaction" in logs
        waf.close()

    def test_process_logging_noop_after_close(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        before = list(fake_abi.call_log)
        tx.process_logging()  # must not raise
        assert fake_abi.call_log == before
        waf.close()


class TestRequestPipeline:
    def test_process_request_bundle_happy(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_request_bundle(_req(), body=None)
        assert interrupted is False
        tx.close()
        waf.close()

    def test_process_request_bundle_with_body(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_request_bundle(_req(method="POST"), body=b"hello=1")
        assert ("append_request_body", 7) in fake_abi.call_log
        tx.close()
        waf.close()

    def test_interrupted_via_uri(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_request_bundle(_req(url="/attack"))
        assert interrupted is True
        intr = tx.interruption()
        assert intr is not None
        assert intr.status == 403
        tx.close()
        waf.close()

    def test_phase_calls_short_circuit_after_interrupt(self, fake_abi: FakeLib) -> None:
        """Once a phase interrupts, subsequent phase calls must NOT invoke libcoraza.

        Prevents wasted CRS evaluation on a transaction that has
        already been flagged for block.
        """
        fake_abi.trigger_uri_contains = "/attack"
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_connection("127.0.0.1", 0)
        tx.process_uri("/attack", "GET", "HTTP/1.1")
        assert tx.process_request_headers() is True
        fake_abi.call_log.clear()
        assert tx.process_request_body() is True
        assert not any(c[0] == "process_request_body" for c in fake_abi.call_log)
        assert tx.process_response_headers(200) is True
        assert not any(c[0] == "process_response_headers" for c in fake_abi.call_log)
        assert tx.process_response_body() is True
        assert not any(c[0] == "process_response_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()

    def test_append_request_body_skips_empty(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.append_request_body(b"")
        assert not any(c[0] == "append_request_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()

    def test_add_request_headers(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.add_request_headers([("X-A", "1"), ("X-B", "2")])
        calls = [c for c in fake_abi.call_log if c[0] == "add_request_header"]
        assert len(calls) == 2
        tx.close()
        waf.close()

    def test_process_uri_custom_protocol(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_uri("/x", "GET", "HTTP/2")
        state = fake_abi.txs[id(tx.handle)]
        assert state.protocol == "HTTP/2"
        tx.close()
        waf.close()


class TestResponsePipeline:
    def test_process_response_happy(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=200, headers=(("Content-Type", "text/html"),)),
            body=b"<html>ok</html>",
        )
        assert interrupted is False
        tx.close()
        waf.close()

    def test_interrupted_at_response_headers(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_response_headers_status = 500
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=500, headers=()), body=b""
        )
        assert interrupted is True
        tx.close()
        waf.close()

    def test_interrupted_at_response_body(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_response_body_contains = b"leak"
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=200, headers=()), body=b"secret leak here"
        )
        assert interrupted is True
        tx.close()
        waf.close()

    def test_response_body_skipped_when_not_processable(self, fake_abi: FakeLib) -> None:
        fake_abi.response_body_processable = False
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_response(
            ResponseInfo(status=200, headers=()), body=b"xxx"
        )
        assert not any(c[0] == "append_response_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()

    def test_update_status_code(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.update_status_code(418)
        assert ("update_status_code", 418) in fake_abi.call_log
        tx.close()
        waf.close()

    def test_add_response_headers(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.add_response_headers([("Server", "pycoraza"), ("X", "Y")])
        calls = [c for c in fake_abi.call_log if c[0] == "add_response_header"]
        assert len(calls) == 2
        tx.close()
        waf.close()

    def test_append_response_body_empty_is_noop(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.append_response_body(b"")
        assert not any(c[0] == "append_response_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()


class TestInterruptionAccessor:
    def test_returns_none_without_match(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        assert tx.interruption() is None
        tx.close()
        waf.close()


class TestMatchedRules:
    def test_empty_when_no_match(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        assert tx.matched_rules() == []
        tx.close()
        waf.close()

    def test_populated_via_error_callback(self, fake_abi: FakeLib) -> None:
        from _fake_abi import _InterventionSpec

        # CRS-shape error log. The fake fires the WAF-level error
        # callback during the phase that triggers, so by the time
        # `tx.matched_rules()` is called the chain is recorded.
        fake_abi.trigger_uri_contains = "/attack"
        fake_abi.interruption_spec = _InterventionSpec(
            rule_id=942100,
            data="SQLi attack",
            severity=5,
            error_log=(
                'Coraza: Warning. detected sqli '
                '[file "rules/942.conf"] [line "1"] [id "942100"] '
                '[msg "SQLi attack"] [severity "CRITICAL"]'
            ),
        )
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_request_bundle(_req(url="/attack?x=1"))
        assert interrupted is True
        matches = tx.matched_rules()
        assert len(matches) == 1
        assert matches[0].id == 942100
        assert matches[0].severity == 5
        assert "SQLi attack" in matches[0].message
        tx.close()
        waf.close()

    def test_interruption_rule_id_uses_last_match(self, fake_abi: FakeLib) -> None:
        from _fake_abi import _InterventionSpec

        # Coraza always returns rule_id=0 in the C struct; we overlay
        # it from the last MatchedRule in the chain.
        fake_abi.trigger_uri_contains = "/attack"
        fake_abi.interruption_spec = _InterventionSpec(
            rule_id=0,
            data="anomaly threshold exceeded",
            error_log=(
                '[id "949110"] [msg "Inbound Anomaly Score Exceeded"] '
                '[severity "CRITICAL"]'
            ),
        )
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_request_bundle(_req(url="/attack"))
        intr = tx.interruption()
        assert intr is not None
        assert intr.rule_id == 949110
        tx.close()
        waf.close()

    def test_returns_independent_snapshot(self, fake_abi: FakeLib) -> None:
        from _fake_abi import _InterventionSpec

        fake_abi.trigger_uri_contains = "/attack"
        fake_abi.interruption_spec = _InterventionSpec(
            rule_id=1234,
            error_log='[id "1234"] [msg "x"]',
        )
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_request_bundle(_req(url="/attack"))
        snap = tx.matched_rules()
        snap.clear()
        # Mutating the snapshot must not affect the canonical list.
        assert len(tx.matched_rules()) == 1
        tx.close()
        waf.close()


class TestInspectabilityPredicates:
    """`is_rule_engine_off` / `is_request_body_accessible` /
    `is_response_body_accessible` are forward-looking predicates that
    upstream libcoraza does not yet expose. The wrapper falls back to
    `NotImplementedError` when the C symbol is absent.
    """

    def test_rule_engine_off_true_when_lib_returns_one(self, fake_abi: FakeLib) -> None:
        fake_abi.rule_engine_off = True
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            assert tx.is_rule_engine_off() is True
        finally:
            tx.close()
            waf.close()

    def test_rule_engine_off_false_when_engine_on(self, fake_abi: FakeLib) -> None:
        # SecLang: `SecRuleEngine On` — predicate should report False.
        fake_abi.rule_engine_off = False
        waf = _make_waf(mode=ProcessMode.BLOCK)
        tx = waf.new_transaction()
        try:
            assert tx.is_rule_engine_off() is False
        finally:
            tx.close()
            waf.close()

    def test_rule_engine_off_raises_when_lib_lacks_symbol(self, fake_abi: FakeLib) -> None:
        # Simulate the current upstream libcoraza state: the C symbol is
        # not exported. The wrapper must raise NotImplementedError, not
        # silently return a value (silent default would be a bypass).
        fake_abi.missing_symbols.add("coraza_is_rule_engine_off")
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            with pytest.raises(NotImplementedError, match="coraza_is_rule_engine_off"):
                tx.is_rule_engine_off()
        finally:
            tx.close()
            waf.close()

    def test_request_body_accessible_true(self, fake_abi: FakeLib) -> None:
        fake_abi.request_body_accessible = True
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            assert tx.is_request_body_accessible() is True
        finally:
            tx.close()
            waf.close()

    def test_request_body_accessible_false(self, fake_abi: FakeLib) -> None:
        fake_abi.request_body_accessible = False
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            assert tx.is_request_body_accessible() is False
        finally:
            tx.close()
            waf.close()

    def test_request_body_accessible_raises_when_lib_lacks_symbol(
        self, fake_abi: FakeLib
    ) -> None:
        fake_abi.missing_symbols.add("coraza_is_request_body_accessible")
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            with pytest.raises(
                NotImplementedError, match="coraza_is_request_body_accessible"
            ):
                tx.is_request_body_accessible()
        finally:
            tx.close()
            waf.close()

    def test_response_body_accessible_true(self, fake_abi: FakeLib) -> None:
        fake_abi.response_body_accessible = True
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            assert tx.is_response_body_accessible() is True
        finally:
            tx.close()
            waf.close()

    def test_response_body_accessible_false(self, fake_abi: FakeLib) -> None:
        fake_abi.response_body_accessible = False
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            assert tx.is_response_body_accessible() is False
        finally:
            tx.close()
            waf.close()

    def test_response_body_accessible_raises_when_lib_lacks_symbol(
        self, fake_abi: FakeLib
    ) -> None:
        fake_abi.missing_symbols.add("coraza_is_response_body_accessible")
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            with pytest.raises(
                NotImplementedError, match="coraza_is_response_body_accessible"
            ):
                tx.is_response_body_accessible()
        finally:
            tx.close()
            waf.close()


class TestReset:
    """`Transaction.reset()` is intended for keep-alive reuse. Until
    upstream libcoraza ships `coraza_reset_transaction`, every call
    raises `NotImplementedError` so callers fall back to creating a new
    transaction (the safe path)."""

    def test_reset_when_lib_lacks_symbol_raises(self, fake_abi: FakeLib) -> None:
        # Mirror current upstream — no symbol exported.
        fake_abi.missing_symbols.add("coraza_reset_transaction")
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            with pytest.raises(NotImplementedError, match="not supported"):
                tx.reset()
        finally:
            tx.close()
            waf.close()

    def test_reset_threads_through_when_lib_supports_it(
        self, fake_abi: FakeLib
    ) -> None:
        # Forward-compat check: once libcoraza ships the symbol, the
        # wrapper invokes it. The fake's default implementation clears
        # interruption state on the underlying handle.
        fake_abi.trigger_uri_contains = "/attack"
        waf = _make_waf()
        tx = waf.new_transaction()
        try:
            tx.process_request_bundle(_req(url="/attack"))
            assert tx.interruption() is not None
            tx.reset()
            assert ("reset_transaction",) in fake_abi.call_log
        finally:
            tx.close()
            waf.close()
