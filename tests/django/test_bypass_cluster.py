"""Regression: Django request-side bypass cluster (security).

Mirrors ``tests/flask/test_bypass_cluster.py`` against Django's
WSGI middleware. Same WSGI collapse limitation, same skip-bypass
shape with RFC 3986 ``;...`` parameters.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

django = pytest.importorskip("django")

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.django import CorazaMiddleware


def _plain(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok", content_type="text/plain")


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    keys = ["PYCORAZA_WAF", "PYCORAZA_ON_BLOCK", "PYCORAZA_INSPECT_RESPONSE",
            "PYCORAZA_ON_WAF_ERROR", "PYCORAZA_SKIP"]
    for k in keys:
        if hasattr(settings, k):
            delattr(settings, k)
    yield
    for k in keys:
        if hasattr(settings, k):
            delattr(settings, k)


def _mk_waf():
    return create_waf(
        WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK)
    )


def _capture_request_headers(
    fake_abi: FakeLib,
) -> list[tuple[str, str]]:
    captured: list[tuple[str, str]] = []
    real = fake_abi.coraza_add_request_header

    def cap(tx, name, name_len, value, value_len):
        nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
        vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
        captured.append((nm, vl))
        return real(tx, name, name_len, value, value_len)

    fake_abi.coraza_add_request_header = cap  # type: ignore[assignment]
    return captured


class TestC1MultiValueHeaderSplit:
    def test_xforwarded_for_split_into_distinct_tuples(
        self, fake_abi: FakeLib
    ) -> None:
        """Django's ``request.META`` collapses repeated headers like
        WSGI does. The middleware re-splits the RFC 7230 list-valued
        set so the WAF sees each entry as its own tuple."""
        requests = _capture_request_headers(fake_abi)
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)

        # Construct the env shape Django sees from a proxy that merged
        # two upstream X-Forwarded-For lines.
        request = RequestFactory().get(
            "/", HTTP_X_FORWARDED_FOR="10.0.0.1, 10.0.0.2"
        )
        rv = mw(request)
        assert rv.status_code == 200

        xff = [v for n, v in requests if n.lower() == "x-forwarded-for"]
        assert xff == ["10.0.0.1", "10.0.0.2"], (
            f"WAF must see split tuples, got {xff!r}"
        )

    def test_accept_split_recovers_each_media_range(
        self, fake_abi: FakeLib
    ) -> None:
        requests = _capture_request_headers(fake_abi)
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)

        request = RequestFactory().get(
            "/", HTTP_ACCEPT="application/json, text/html"
        )
        rv = mw(request)
        assert rv.status_code == 200

        accepts = [v for n, v in requests if n.lower() == "accept"]
        assert "application/json" in accepts
        assert "text/html" in accepts

    def test_singular_user_agent_not_split(self, fake_abi: FakeLib) -> None:
        """``User-Agent`` is singular per RFC 7231; a comma in the
        UA value (e.g. ``Browser/1.0, custom``) must pass through."""
        requests = _capture_request_headers(fake_abi)
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)

        ua = "Mozilla/5.0 (X, Y) Custom/1.0"
        request = RequestFactory().get("/", HTTP_USER_AGENT=ua)
        rv = mw(request)
        assert rv.status_code == 200

        uas = [v for n, v in requests if n.lower() == "user-agent"]
        assert uas == [ua]


class TestH1SkipBypassNormalization:
    def test_admin_with_path_param_is_not_skipped(
        self, fake_abi: FakeLib
    ) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)
        mw(RequestFactory().get("/admin;.png"))

        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds, (
            "WAF must evaluate /admin;.png; ext-skip bypass is now closed"
        )

    def test_static_png_still_skipped(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)
        mw(RequestFactory().get("/static/foo.png"))

        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" not in kinds

    def test_admin_plain_still_evaluated(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain)
        mw(RequestFactory().get("/admin"))

        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds
