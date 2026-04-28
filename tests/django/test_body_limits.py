"""Body-limits behavior for the Django middleware.

Mirrors the Flask and Starlette body-limit suites. Django reads the
body lazily through ``request.body``; the middleware drains the
underlying stream first, feeds the WAF in chunks, then primes
``request._body`` so the view sees byte-identical input.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

django = pytest.importorskip("django")

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from pycoraza import BodyLimits, ProcessMode, WAFConfig, create_waf
from pycoraza.django import CorazaMiddleware

_DOWNSTREAM_HITS: list[int] = []


def _view(request: HttpRequest) -> HttpResponse:
    body = request.body or b""
    _DOWNSTREAM_HITS.append(len(body))
    return HttpResponse(str(len(body)), content_type="text/plain")


@pytest.fixture(autouse=True)
def _reset_settings_and_hits() -> None:
    _DOWNSTREAM_HITS.clear()
    for key in (
        "PYCORAZA_WAF",
        "PYCORAZA_ON_BLOCK",
        "PYCORAZA_INSPECT_RESPONSE",
        "PYCORAZA_ON_WAF_ERROR",
        "PYCORAZA_SKIP",
        "PYCORAZA_BODY_LIMITS",
    ):
        if hasattr(settings, key):
            delattr(settings, key)
    yield
    for key in (
        "PYCORAZA_WAF",
        "PYCORAZA_ON_BLOCK",
        "PYCORAZA_INSPECT_RESPONSE",
        "PYCORAZA_ON_WAF_ERROR",
        "PYCORAZA_SKIP",
        "PYCORAZA_BODY_LIMITS",
    ):
        if hasattr(settings, key):
            delattr(settings, key)


def _mw(body_limits: BodyLimits | None = None) -> CorazaMiddleware:
    settings.PYCORAZA_WAF = create_waf(
        WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK)
    )
    if body_limits is not None:
        settings.PYCORAZA_BODY_LIMITS = body_limits
    return CorazaMiddleware(_view)


class TestSmallBody:
    def test_under_limit_unchanged(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(max_in_memory=4096, max_total=8192))
        body = b"hello=world"
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 200
        assert rv.content == str(len(body)).encode()
        assert [len(body)] == _DOWNSTREAM_HITS


class TestMediumBody:
    def test_spools_when_over_in_memory(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(max_in_memory=1024, max_total=65536))
        body = b"M" * 8192
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 200
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == len(body)
        assert [len(body)] == _DOWNSTREAM_HITS


class TestOverflowBlock:
    def test_returns_413_and_skips_downstream(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(max_in_memory=512, max_total=1024, on_overflow="block"))
        body = b"B" * 4096
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 413
        assert _DOWNSTREAM_HITS == []
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == 1024


class TestOverflowSkip:
    def test_bypasses_waf_and_forwards_full_body(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(max_in_memory=512, max_total=1024, on_overflow="skip"))
        body = b"S" * 4096
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 200
        assert [len(body)] == _DOWNSTREAM_HITS
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_request_body" not in kinds


class TestOverflowEvaluatePartial:
    def test_waf_sees_prefix_downstream_sees_full(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(
            max_in_memory=512, max_total=1024, on_overflow="evaluate_partial"
        ))
        body = b"P" * 4096
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 200
        assert [len(body)] == _DOWNSTREAM_HITS
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == 1024
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_request_body" in kinds


class TestDefaultsFailClosed:
    def test_default_overflow_is_block(self, fake_abi: FakeLib) -> None:
        mw = _mw(BodyLimits(max_in_memory=128, max_total=256))
        body = b"D" * 1024
        rv = mw(RequestFactory().post(
            "/echo", data=body, content_type="application/octet-stream"
        ))
        assert rv.status_code == 413
        assert _DOWNSTREAM_HITS == []
