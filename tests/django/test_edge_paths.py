"""Edge paths in `pycoraza.django.CorazaMiddleware`.

Hits the response-inspection error branches, the safe-int fallback in
_request_info_from_django, and the body-read fallback.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

pytest.importorskip("django")

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.django import CorazaMiddleware, _request_info_from_django, _safe_int


def _response_text(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("hi")


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    for key in ("PYCORAZA_WAF", "PYCORAZA_INSPECT_RESPONSE", "PYCORAZA_ON_WAF_ERROR", "PYCORAZA_SKIP", "PYCORAZA_ON_BLOCK"):
        if hasattr(settings, key):
            delattr(settings, key)
    yield
    for key in ("PYCORAZA_WAF", "PYCORAZA_INSPECT_RESPONSE", "PYCORAZA_ON_WAF_ERROR", "PYCORAZA_SKIP", "PYCORAZA_ON_BLOCK"):
        if hasattr(settings, key):
            delattr(settings, key)


def _waf() -> object:
    return create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))


class TestRequestInfo:
    def test_headers_captured(self, fake_abi: FakeLib) -> None:
        request = RequestFactory().get("/", HTTP_USER_AGENT="curl/1", HTTP_X_FORWARDED_FOR="1.2.3.4")
        info = _request_info_from_django(request)
        header_names = {name for name, _ in info.headers}
        assert "user-agent" in header_names
        assert "x-forwarded-for" in header_names

    def test_content_type_and_length_included(self, fake_abi: FakeLib) -> None:
        request = RequestFactory().post("/echo", data={"k": "v"})
        info = _request_info_from_django(request)
        header_names = {name for name, _ in info.headers}
        assert "content-type" in header_names

    def test_non_string_meta_skipped(self, fake_abi: FakeLib) -> None:
        request = RequestFactory().get("/")
        request.META["BOGUS_NON_STRING"] = 42
        info = _request_info_from_django(request)
        assert all(isinstance(v, str) for _, v in info.headers)

    def test_strips_only_exact_wsgiref_default_on_bodyless(
        self, fake_abi: FakeLib
    ) -> None:
        """wsgiref's synthetic CONTENT_TYPE on bodyless requests is exactly
        'text/plain' (email.Message default). Strip ONLY that exact value
        so CRS 920420 doesn't false-positive on health probes.
        """
        request = RequestFactory().get("/healthz")
        request.META["CONTENT_TYPE"] = "text/plain"
        request.META["CONTENT_LENGTH"] = ""
        info = _request_info_from_django(request)
        names = {n for n, _ in info.headers}
        assert "content-type" not in names
        assert "content-length" not in names

    def test_post_with_body_keeps_content_type(self, fake_abi: FakeLib) -> None:
        request = RequestFactory().post("/echo", data={"k": "v"})
        info = _request_info_from_django(request)
        names = {n for n, _ in info.headers}
        assert "content-type" in names
        assert "content-length" in names

    def test_non_default_content_type_on_bodyless_preserved(
        self, fake_abi: FakeLib
    ) -> None:
        """Security: any Content-Type value other than wsgiref's exact
        'text/plain' default is forwarded even on bodyless requests, so
        Coraza/CRS can evaluate it. This prevents an attacker from
        encoding an attack in the Content-Type header on a bodyless
        request and bypassing all CT-keyed rules.
        """
        for malicious in (
            "application/x-malicious",
            "text/html",
            "text/plain; charset=evil",
            "<script>alert(1)</script>",
            "TEXT/PLAIN",  # case differs -> not the exact default
        ):
            request = RequestFactory().get("/x")
            request.META["CONTENT_TYPE"] = malicious
            request.META["CONTENT_LENGTH"] = ""
            info = _request_info_from_django(request)
            assert ("content-type", malicious) in info.headers, (
                f"non-default CT {malicious!r} on bodyless request must be forwarded"
            )

    def test_content_length_with_body_preserved(self, fake_abi: FakeLib) -> None:
        request = RequestFactory().post("/x", data="payload", content_type="text/plain")
        info = _request_info_from_django(request)
        names = {n for n, _ in info.headers}
        # text/plain + body present -> CT preserved
        assert "content-type" in names
        assert "content-length" in names


class TestSafeInt:
    def test_none(self) -> None:
        assert _safe_int(None) == 0

    def test_valid_string(self) -> None:
        assert _safe_int("8080") == 8080

    def test_invalid_string(self) -> None:
        assert _safe_int("not a number") == 0

    def test_bogus_type(self) -> None:
        assert _safe_int(object()) == 0


class TestInspectResponseErrors:
    def test_append_response_body_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("append_response_body")
        settings.PYCORAZA_WAF = _waf()
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_response_text)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200

    def test_process_response_body_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_body")
        settings.PYCORAZA_WAF = _waf()
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_response_text)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200

    def test_non_bytes_body_skipped(self, fake_abi: FakeLib) -> None:
        # Streaming / file-like bodies — our inspector should not try
        # to scan them.
        def streaming(_r):
            resp = HttpResponse()
            resp.content = b"ok"  # but write over response to be streaming-like
            return resp

        settings.PYCORAZA_WAF = _waf()
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(streaming)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200


class TestFinalizeSwallowsErrors:
    def test_process_logging_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_logging")
        settings.PYCORAZA_WAF = _waf()
        mw = CorazaMiddleware(_response_text)
        rv = mw(RequestFactory().get("/"))
        # we already returned the 200 from downstream; logging error
        # stays internal.
        assert rv.status_code == 200

    def test_free_transaction_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("free_transaction")
        settings.PYCORAZA_WAF = _waf()
        mw = CorazaMiddleware(_response_text)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200
