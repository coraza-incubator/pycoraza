"""`WAFPool` — shared WAF handle across workers."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

from pycoraza import ProcessMode, WAFConfig, create_waf_pool


class TestConstruction:
    def test_builds_waf(self, fake_abi: FakeLib) -> None:
        pool = create_waf_pool(WAFConfig(rules="r", mode=ProcessMode.BLOCK))
        assert pool.size == 1
        assert pool.mode is ProcessMode.BLOCK
        assert pool.waf is not None
        pool.close()

    def test_size_greater_than_one(self, fake_abi: FakeLib) -> None:
        pool = create_waf_pool(WAFConfig(rules="r"), size=8)
        assert pool.size == 8
        pool.close()

    def test_size_zero_rejected(self, fake_abi: FakeLib) -> None:
        with pytest.raises(ValueError):
            create_waf_pool(WAFConfig(rules="r"), size=0)

    def test_size_negative_rejected(self, fake_abi: FakeLib) -> None:
        with pytest.raises(ValueError):
            create_waf_pool(WAFConfig(rules="r"), size=-1)


class TestContextManager:
    def test_context(self, fake_abi: FakeLib) -> None:
        with create_waf_pool(WAFConfig(rules="r")) as pool:
            tx = pool.new_transaction()
            tx.close()
        assert any(c[0] == "free_waf" for c in fake_abi.call_log)


class TestNewTransaction:
    def test_passes_tx_id(self, fake_abi: FakeLib) -> None:
        pool = create_waf_pool(WAFConfig(rules="r"))
        tx = pool.new_transaction("req-1")
        tx.close()
        pool.close()
        assert any(c[0] == "new_transaction_with_id" for c in fake_abi.call_log)
