"""Edge cases in `pycoraza.abi` that the happy-path tests miss."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib, _FakeCData

from pycoraza import CorazaError
from pycoraza.abi import Abi, _from_c


class TestRulesMergeError:
    def test_rules_merge_returns_nonzero_raises(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("rules_merge")
        abi = Abi()
        cfg = abi.new_waf_config()
        waf_a = abi.new_waf(cfg)
        waf_b = abi.new_waf(cfg)
        with pytest.raises(CorazaError, match="coraza_rules_merge failed"):
            abi.rules_merge(waf_a, waf_b)


class TestRulesMergeHappy:
    def test_rules_merge_rc_zero(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        abi.rules_add(cfg, "SecRule ARGS \"@rx foo\" \"id:1,phase:1,pass\"")
        waf_a = abi.new_waf(cfg)
        waf_b = abi.new_waf(cfg)
        abi.rules_merge(waf_a, waf_b)
        assert ("rules_merge",) in fake_abi.call_log


class TestNewWafConfigNull:
    def test_returns_null_raises(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_waf_config = True
        abi = Abi()
        with pytest.raises(CorazaError, match="coraza_new_waf_config"):
            abi.new_waf_config()


class TestFromCDefensive:
    def test_null_pointer_returns_none(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert _from_c(abi.ffi, abi.ffi.NULL) is None

    def test_none_pointer_returns_none(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert _from_c(abi.ffi, None) is None

    def test_bytes_pointer_decoded(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert _from_c(abi.ffi, _FakeCData(b"hello")) == "hello"

    def test_invalid_utf8_replaced(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        raw = _FakeCData(b"\xff\xfe\xfd")
        result = _from_c(abi.ffi, raw)
        assert isinstance(result, str)


class TestCorazaErrorCheck:
    def test_negative_rc_raises_with_op_name(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        with pytest.raises(CorazaError, match="libcoraza test_op failed: rc=-1"):
            abi._check(-1, "test_op")

    def test_rc_zero_returns_zero(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert abi._check(0, "test_op") == 0

    def test_rc_one_returns_one(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        assert abi._check(1, "test_op") == 1
