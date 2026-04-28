"""`WAFRef` — thin reference wrapper around a single WAF."""

from __future__ import annotations

from _fake_abi import FakeLib

from pycoraza import (
    WAFRef,
    ProcessMode,
    WAFConfig,
    create_waf_ref,
)


class TestWAFRefConstruction:
    def test_builds_waf(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r", mode=ProcessMode.BLOCK))
        assert ref.mode is ProcessMode.BLOCK
        assert ref.waf is not None
        ref.close()

    def test_direct_construction(self, fake_abi: FakeLib) -> None:
        ref = WAFRef(WAFConfig(rules="r"))
        ref.close()


class TestWAFRefSurface:
    def test_logger_property(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r"))
        assert ref.logger is ref.waf.logger
        ref.close()

    def test_destroyed_property(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r"))
        assert ref.destroyed is False
        ref.close()
        assert ref.destroyed is True

    def test_context_manager(self, fake_abi: FakeLib) -> None:
        with create_waf_ref(WAFConfig(rules="r")) as ref:
            tx = ref.new_transaction()
            tx.close()
        assert any(c[0] == "free_waf" for c in fake_abi.call_log)


class TestWAFRefNewTransaction:
    def test_passes_tx_id(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r"))
        tx = ref.new_transaction("req-1")
        tx.close()
        ref.close()
        assert any(c[0] == "new_transaction_with_id" for c in fake_abi.call_log)
