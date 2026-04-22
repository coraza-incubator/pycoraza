"""`WAF` + `create_waf` lifecycle."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

from pycoraza import CorazaError, ProcessMode, WAFConfig, create_waf, silent_logger


class TestCreateWaf:
    def test_adds_rules_then_frees_config(self, fake_abi: FakeLib) -> None:
        cfg = WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK)
        waf = create_waf(cfg)
        kinds = [c[0] for c in fake_abi.call_log]
        assert kinds.index("new_waf_config") < kinds.index("rules_add")
        assert kinds.index("rules_add") < kinds.index("new_waf")
        assert "free_waf_config" in kinds
        waf.close()

    def test_returns_waf_with_mode(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r", mode=ProcessMode.BLOCK))
        assert waf.mode is ProcessMode.BLOCK
        waf.close()

    def test_default_logger_is_silent(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        assert waf.logger is not None
        waf.close()

    def test_preserves_user_logger(self, fake_abi: FakeLib) -> None:
        log = silent_logger()
        waf = create_waf(WAFConfig(rules="r", logger=log))
        assert waf.logger is log
        waf.close()

    def test_new_waf_failure_still_frees_config(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_waf = True
        with pytest.raises(CorazaError):
            create_waf(WAFConfig(rules="r"))
        assert ("free_waf_config",) in fake_abi.call_log


class TestWAFHandle:
    def test_handle_returns_opaque(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        assert waf.handle is not None
        waf.close()

    def test_handle_after_close_raises(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        waf.close()
        with pytest.raises(CorazaError):
            _ = waf.handle

    def test_close_idempotent(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        waf.close()
        waf.close()  # second close must not raise

    def test_rules_count(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="A\nB\n"))
        assert waf.rules_count() >= 1
        waf.close()

    def test_new_transaction_returns_tx(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        tx = waf.new_transaction()
        assert tx is not None
        tx.close()
        waf.close()

    def test_new_transaction_with_id(self, fake_abi: FakeLib) -> None:
        waf = create_waf(WAFConfig(rules="r"))
        tx = waf.new_transaction(tx_id="abc")
        assert any(c[0] == "new_transaction_with_id" for c in fake_abi.call_log)
        tx.close()
        waf.close()


class TestContextManager:
    def test_enter_exit_closes(self, fake_abi: FakeLib) -> None:
        with create_waf(WAFConfig(rules="r")) as waf:
            assert waf.handle is not None
        with pytest.raises(CorazaError):
            _ = waf.handle
