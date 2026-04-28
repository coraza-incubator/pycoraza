"""Dataclass / enum sanity."""

from __future__ import annotations

import pytest

from pycoraza import (
    Interruption,
    MatchedRule,
    OnWAFError,
    ProcessMode,
    RequestInfo,
    ResponseInfo,
    SkipOptions,
    WAFConfig,
)


class TestProcessMode:
    def test_string_values(self) -> None:
        assert ProcessMode.DETECT.value == "detect"
        assert ProcessMode.BLOCK.value == "block"

    def test_str_enum(self) -> None:
        assert ProcessMode("detect") is ProcessMode.DETECT
        assert ProcessMode("block") is ProcessMode.BLOCK

    def test_is_str(self) -> None:
        assert isinstance(ProcessMode.DETECT, str)


class TestOnWAFError:
    def test_values(self) -> None:
        assert OnWAFError("block") is OnWAFError.BLOCK
        assert OnWAFError("allow") is OnWAFError.ALLOW

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError):
            OnWAFError("explode")


class TestWAFConfig:
    def test_defaults(self) -> None:
        cfg = WAFConfig(rules="SecRuleEngine On")
        assert cfg.rules == "SecRuleEngine On"
        assert cfg.mode is ProcessMode.DETECT
        assert cfg.logger is None

    def test_with_mode(self) -> None:
        cfg = WAFConfig(rules="", mode=ProcessMode.BLOCK)
        assert cfg.mode is ProcessMode.BLOCK


class TestInterruption:
    def test_frozen(self) -> None:
        intr = Interruption(rule_id=1, action="deny", status=403, data="x")
        with pytest.raises(Exception):
            intr.rule_id = 2  # type: ignore[misc]

    def test_source_optional(self) -> None:
        intr = Interruption(rule_id=1, action="deny", status=403, data="x")
        assert intr.source is None


class TestMatchedRule:
    def test_fields(self) -> None:
        rule = MatchedRule(id=42, severity=3, message="hi")
        assert rule.id == 42
        assert rule.severity == 3
        assert rule.message == "hi"


class TestRequestInfo:
    def test_defaults(self) -> None:
        req = RequestInfo(method="GET", url="/", headers=())
        assert req.protocol == "HTTP/1.1"
        assert req.remote_addr == ""
        assert req.remote_port == 0
        assert req.server_port == 0


class TestResponseInfo:
    def test_defaults(self) -> None:
        rsp = ResponseInfo(status=200, headers=())
        assert rsp.protocol == "HTTP/1.1"


class TestSkipOptions:
    def test_defaults_have_common_assets(self) -> None:
        opts = SkipOptions()
        assert ".png" in opts.extensions
        assert ".css" in opts.extensions
        assert "/_next/static/" in opts.prefixes
        assert "/assets/" in opts.prefixes
        assert "/favicon.ico" in opts.prefixes
        # /static/ was dropped from the default prefix set: the WAF
        # bypassing every route under /static/ is too aggressive when
        # apps mount real handlers there. Opt back in via
        # SkipOptions.unsafe_legacy_static_prefix() if you need it.
        assert "/static/" not in opts.prefixes
        assert opts.extra_paths == ()

    def test_unsafe_legacy_static_prefix_helper(self) -> None:
        assert SkipOptions.unsafe_legacy_static_prefix() == ("/static/",)
        opts = SkipOptions(
            prefixes=SkipOptions.default_prefixes()
            + SkipOptions.unsafe_legacy_static_prefix(),
        )
        assert "/static/" in opts.prefixes

    def test_extra_paths_are_independent(self) -> None:
        a = SkipOptions()
        b = SkipOptions()
        assert a.extra_paths is not b.extra_paths or a.extra_paths == ()
