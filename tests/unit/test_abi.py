"""`Abi` — exercised against the fake libcoraza bindings."""

from __future__ import annotations

import pytest

from _fake_abi import FakeLib

from pycoraza import CorazaError
from pycoraza.abi import Abi


class TestLifecycle:
    def test_new_and_free_config(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        assert cfg is not None
        abi.free_waf_config(cfg)
        assert ("new_waf_config",) in fake_abi.call_log
        assert ("free_waf_config",) in fake_abi.call_log

    def test_rules_add_and_new_waf(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        abi.rules_add(cfg, "SecRuleEngine On\n")
        waf = abi.new_waf(cfg)
        assert waf is not None
        assert abi.rules_count(waf) == 1

    def test_new_waf_null_raises(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        fake_abi.raise_on_new_waf = True
        with pytest.raises(CorazaError):
            abi.new_waf(cfg)

    def test_new_transaction_with_id(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf, tx_id="req-42")
        assert fake_abi.txs[id(tx)].tx_id == "req-42"

    def test_new_transaction_null_raises(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        fake_abi.raise_on_new_transaction = True
        with pytest.raises(CorazaError):
            abi.new_transaction(waf)


class TestProcessing:
    def test_process_connection_propagates_args(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.process_connection(tx, "10.0.0.1", 5000, "", 0)
        state = fake_abi.txs[id(tx)]
        assert state.client_ip == "10.0.0.1"
        assert state.client_port == 5000

    def test_process_uri_and_headers(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.process_uri(tx, "/x?q=1", "GET", "HTTP/1.1")
        abi.add_request_header(tx, "Host", "example.com")
        abi.add_request_headers(tx, [("User-Agent", "ua"), ("Accept", "*/*")])
        state = fake_abi.txs[id(tx)]
        assert state.uri == "/x?q=1"
        assert state.method == "GET"
        assert ("User-Agent", "ua") in state.request_headers

    def test_request_body_and_process(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.append_request_body(tx, b"hello")
        rc = abi.process_request_body(tx)
        assert rc == 0
        state = fake_abi.txs[id(tx)]
        assert state.request_body == [b"hello"]

    def test_response_body_and_process(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.process_response_headers(tx, 200, "HTTP/1.1")
        abi.append_response_body(tx, b"body")
        abi.process_response_body(tx)
        assert abi.is_response_body_processable(tx) is True

    def test_is_response_body_processable_false(self, fake_abi: FakeLib) -> None:
        fake_abi.response_body_processable = False
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        assert abi.is_response_body_processable(tx) is False

    def test_process_logging_marks_tx(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.process_logging(tx)
        assert fake_abi.txs[id(tx)].logged is True


class TestIntervention:
    def test_no_intervention(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        assert abi.intervention(tx) is None

    def test_intervention_returned(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        abi.process_uri(tx, "/attack?x=1", "GET", "HTTP/1.1")
        intr = abi.intervention(tx)
        assert intr is not None
        assert intr.status == 403
        assert intr.action == "deny"
        assert intr.rule_id == 1001
        assert ("free_intervention",) in fake_abi.call_log


class TestErrorTranslation:
    def test_negative_rc_raises(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_request_headers")
        abi = Abi()
        cfg = abi.new_waf_config()
        waf = abi.new_waf(cfg)
        tx = abi.new_transaction(waf)
        with pytest.raises(CorazaError):
            abi.process_request_headers(tx)


class TestCallbacks:
    def test_register_error_callback(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        received: list[tuple[int, str]] = []
        abi.register_error_callback(cfg, lambda sev, log: received.append((sev, log)))
        from _fake_abi import _FakeCData

        cb = fake_abi.configs[id(cfg)].error_callback
        assert cb is not None
        cb(None, _FakeCData(b""))
        assert received and received[0][0] == 3
        assert received[0][1] == "fake error log"

    def test_register_debug_callback(self, fake_abi: FakeLib) -> None:
        from _fake_abi import _FakeCData

        abi = Abi()
        cfg = abi.new_waf_config()
        received: list[tuple[int, str, str]] = []
        abi.register_debug_callback(
            cfg, lambda lvl, m, f: received.append((lvl, m, f))
        )
        cb = fake_abi.configs[id(cfg)].debug_callback
        assert cb is not None
        cb(None, 2, _FakeCData(b"msg"), _FakeCData(b"fields"))
        assert received == [(2, "msg", "fields")]


class TestProperties:
    def test_exposes_ffi_and_lib(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert abi.ffi is not None
        assert abi.lib is fake_abi

    def test_singleton_bindings(self, fake_abi: FakeLib) -> None:
        a = Abi()
        b = Abi()
        assert a.lib is b.lib
