"""`WAFRef` — thin reference wrapper around a single WAF.

Also covers the deprecated `WAFPool` / `create_waf_pool` aliases
that exist for compatibility with pre-rename user code.
"""

from __future__ import annotations

import warnings

import pytest
from _fake_abi import FakeLib

from pycoraza import (
    WAFRef,
    ProcessMode,
    WAFConfig,
    create_waf_ref,
)
from pycoraza import WAFPool, create_waf_pool  # deprecated alias


class TestWAFRefConstruction:
    def test_builds_waf(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r", mode=ProcessMode.BLOCK))
        assert ref.size == 1
        assert ref.mode is ProcessMode.BLOCK
        assert ref.waf is not None
        ref.close()

    def test_size_greater_than_one(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r"), size=8)
        assert ref.size == 8
        ref.close()

    def test_size_zero_rejected(self, fake_abi: FakeLib) -> None:
        with pytest.raises(ValueError):
            create_waf_ref(WAFConfig(rules="r"), size=0)

    def test_size_negative_rejected(self, fake_abi: FakeLib) -> None:
        with pytest.raises(ValueError):
            create_waf_ref(WAFConfig(rules="r"), size=-1)

    def test_direct_construction(self, fake_abi: FakeLib) -> None:
        ref = WAFRef(WAFConfig(rules="r"))
        assert ref.size == 1
        ref.close()


class TestWAFRefSurface:
    def test_logger_property(self, fake_abi: FakeLib) -> None:
        ref = create_waf_ref(WAFConfig(rules="r"))
        # Mirrors the WAF surface: adapters can read `waf.logger`.
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


class TestDeprecatedWAFPoolAlias:
    """Pre-rename code keeps working; users get a DeprecationWarning."""

    def test_wafpool_constructor_warns(self, fake_abi: FakeLib) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            pool = WAFPool(WAFConfig(rules="r"))
            pool.close()
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_create_waf_pool_warns(self, fake_abi: FakeLib) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            pool = create_waf_pool(WAFConfig(rules="r"))
            pool.close()
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_wafpool_is_a_wafref(self, fake_abi: FakeLib) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pool = WAFPool(WAFConfig(rules="r"))
        assert isinstance(pool, WAFRef)
        pool.close()
