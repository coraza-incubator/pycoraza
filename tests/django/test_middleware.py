"""pycoraza.django.CorazaMiddleware — behavior against the fake ABI."""

from __future__ import annotations

import json

import pytest
from _fake_abi import FakeLib

django = pytest.importorskip("django")

from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory

from pycoraza import (
    PROBE_METHODS,
    PROBE_PATHS,
    OnWAFError,
    ProcessMode,
    SkipOptions,
    WAFConfig,
    WAFRef,
    create_waf,
    create_waf_ref,
)
from pycoraza.django import CorazaMiddleware


def _plain_response(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok", content_type="text/plain")


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    to_clear = [
        "PYCORAZA_WAF",
        "PYCORAZA_ON_BLOCK",
        "PYCORAZA_INSPECT_RESPONSE",
        "PYCORAZA_ON_WAF_ERROR",
        "PYCORAZA_SKIP",
    ]
    for key in to_clear:
        if hasattr(settings, key):
            delattr(settings, key)
    yield
    for key in to_clear:
        if hasattr(settings, key):
            delattr(settings, key)


def _mk_waf(mode: ProcessMode = ProcessMode.BLOCK):
    return create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))


class TestConstruction:
    def test_missing_setting_raises_middleware_not_used(self, fake_abi: FakeLib) -> None:
        with pytest.raises(MiddlewareNotUsed):
            CorazaMiddleware(_plain_response)

    def test_happy_construction(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        assert mw is not None

    def test_accepts_wafref(self, fake_abi: FakeLib) -> None:
        # The middleware no longer rejects a non-`WAF` instance — anything
        # that quacks `new_transaction()` (e.g. a `WAFRef`) is fine.
        settings.PYCORAZA_WAF = create_waf_ref(WAFConfig(rules="SecRuleEngine On\n"))
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200


class TestHappyPath:
    def test_benign_request_passes(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200
        assert rv.content == b"ok"

    def test_post_body_read(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        request = RequestFactory().post("/echo", data={"key": "value"})
        rv = mw(request)
        assert rv.status_code == 200
        assert any(c[0] == "append_request_body" for c in fake_abi.call_log)

    def test_logging_and_close_called(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        mw(RequestFactory().get("/"))
        kinds = [c[0] for c in fake_abi.call_log]
        assert kinds.index("process_logging") < kinds.index("free_transaction")


class TestAttackBlocking:
    def test_block_mode_returns_403_json(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        settings.PYCORAZA_WAF = _mk_waf(mode=ProcessMode.BLOCK)
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/attack"))
        assert rv.status_code == 403
        payload = json.loads(rv.content)
        assert payload["error"] == "blocked"
        assert payload["rule_id"] == 1001

    def test_detect_mode_does_not_block(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        settings.PYCORAZA_WAF = _mk_waf(mode=ProcessMode.DETECT)
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/attack"))
        assert rv.status_code == 200

    def test_custom_on_block(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        settings.PYCORAZA_WAF = _mk_waf()

        def on_block(intr, _request):
            return JsonResponse({"custom": True, "rule": intr.rule_id}, status=418)

        settings.PYCORAZA_ON_BLOCK = on_block
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/attack"))
        assert rv.status_code == 418
        assert json.loads(rv.content) == {"custom": True, "rule": 1001}


class TestSkip:
    def test_static_extension_skipped_by_default(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        mw(RequestFactory().get("/static/app.js"))
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)

    def test_probe_paths_not_skipped_by_default(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        mw(RequestFactory().get("/healthz"))
        assert any(c[0] == "new_transaction" for c in fake_abi.call_log)

    def test_probe_preset_opt_in(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        settings.PYCORAZA_SKIP = SkipOptions(
            prefixes=SkipOptions.default_prefixes(),
            extra_paths=PROBE_PATHS,
            methods=PROBE_METHODS,
        )
        mw = CorazaMiddleware(_plain_response)
        mw(RequestFactory().get("/healthz"))
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)

        fake_abi.call_log.clear()
        mw(RequestFactory().options("/api/anything"))
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)


class TestWAFError:
    def test_new_transaction_failure_returns_500(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 500
        assert rv.content == b"waf error"

    def test_on_waf_error_allow(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        settings.PYCORAZA_WAF = _mk_waf()
        settings.PYCORAZA_ON_WAF_ERROR = OnWAFError.ALLOW
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200
        assert rv.content == b"ok"

    def test_on_waf_error_string_literal(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        settings.PYCORAZA_WAF = _mk_waf()
        settings.PYCORAZA_ON_WAF_ERROR = "allow"
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200

    def test_process_uri_failure_blocks(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_uri")
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 500


class TestInspectResponse:
    def test_inspect_response_records_headers(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_response_headers" in kinds
        assert "append_response_body" in kinds

    def test_inspect_response_swallows_waf_errors(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_headers")
        settings.PYCORAZA_WAF = _mk_waf()
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200

    def test_inspect_response_off_by_default(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()
        mw = CorazaMiddleware(_plain_response)
        mw(RequestFactory().get("/"))
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_response_headers" not in kinds

    def test_inspect_response_body_block_enforced(self, fake_abi: FakeLib) -> None:
        # B3: response-side rule fires; with mode=BLOCK the middleware
        # must swap in a block response instead of returning the
        # upstream 200. Earlier versions ran the rule and let the 200
        # through — that was monitor-only enforcement.
        fake_abi.trigger_response_body_contains = b"ok"
        settings.PYCORAZA_WAF = _mk_waf(mode=ProcessMode.BLOCK)
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 403
        payload = json.loads(rv.content)
        assert payload["error"] == "blocked"

    def test_inspect_response_detect_mode_does_not_enforce(
        self, fake_abi: FakeLib
    ) -> None:
        fake_abi.trigger_response_body_contains = b"ok"
        settings.PYCORAZA_WAF = _mk_waf(mode=ProcessMode.DETECT)
        settings.PYCORAZA_INSPECT_RESPONSE = True
        mw = CorazaMiddleware(_plain_response)
        rv = mw(RequestFactory().get("/"))
        assert rv.status_code == 200


class TestDownstreamException:
    def test_downstream_raise_still_finalizes(self, fake_abi: FakeLib) -> None:
        settings.PYCORAZA_WAF = _mk_waf()

        def boom(_request):
            raise ValueError("downstream crash")

        mw = CorazaMiddleware(boom)
        with pytest.raises(ValueError):
            mw(RequestFactory().get("/"))
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in kinds
        assert "free_transaction" in kinds
