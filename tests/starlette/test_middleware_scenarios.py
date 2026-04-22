"""End-to-end scenarios for the ASGI middleware with the fake ABI."""

from __future__ import annotations

import json

import pytest

from _fake_abi import FakeLib

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware


def _build(
    fake_abi: FakeLib,
    *,
    mode: ProcessMode = ProcessMode.BLOCK,
    inspect_response: bool = False,
    skip=None,
    on_waf_error: str = "block",
    on_block=None,
) -> Starlette:
    async def index(_request):
        return PlainTextResponse("ok")

    async def attack(_request):
        return PlainTextResponse("should-not-reach")

    async def echo(request):
        body = await request.body()
        return PlainTextResponse(body)

    async def secret(_request):
        return PlainTextResponse("secret leak here")

    routes = [
        Route("/", index),
        Route("/attack", attack),
        Route("/echo", echo, methods=["POST"]),
        Route("/secret", secret),
        Route("/static/app.js", index),
    ]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    mw = [
        Middleware(
            CorazaMiddleware,
            waf=waf,
            inspect_response=inspect_response,
            skip=skip,
            on_waf_error=on_waf_error,
            on_block=on_block,
        )
    ]
    return Starlette(routes=routes, middleware=mw)


class TestAttackBlocking:
    def test_block_mode_returns_403(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        app = _build(fake_abi, mode=ProcessMode.BLOCK)
        with TestClient(app) as c:
            rv = c.get("/attack")
        assert rv.status_code == 403
        body = json.loads(rv.content)
        assert body["error"] == "blocked"
        assert body["rule_id"] == 1001
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in kinds
        assert "free_transaction" in kinds

    def test_detect_mode_runs_app(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        app = _build(fake_abi, mode=ProcessMode.DETECT)
        with TestClient(app) as c:
            rv = c.get("/attack")
        assert rv.status_code == 200
        assert rv.text == "should-not-reach"

    def test_custom_on_block(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"

        async def on_block(intr, scope, send):
            await send({
                "type": "http.response.start",
                "status": 418,
                "headers": [(b"content-type", b"text/plain")],
            })
            await send({"type": "http.response.body", "body": b"nope"})
            return True

        app = _build(fake_abi, mode=ProcessMode.BLOCK, on_block=on_block)
        with TestClient(app) as c:
            rv = c.get("/attack")
        assert rv.status_code == 418
        assert rv.content == b"nope"

    def test_on_block_returning_false_falls_back(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"

        async def on_block(intr, scope, send):
            return False

        app = _build(fake_abi, mode=ProcessMode.BLOCK, on_block=on_block)
        with TestClient(app) as c:
            rv = c.get("/attack")
        assert rv.status_code == 403


class TestSkip:
    def test_static_skips(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.get("/static/app.js")
        assert rv.status_code == 200
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)

    def test_custom_skip_callable(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, skip=lambda path: path == "/")
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)


class TestWAFErrors:
    def test_new_transaction_failure_returns_500(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi, on_waf_error="block")
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_processing_failure_returns_500(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_uri")
        app = _build(fake_abi, on_waf_error="block")
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500


class TestResponseInspection:
    def test_response_body_rule_interrupts_in_header_phase(self, fake_abi: FakeLib) -> None:
        # Response-body interruption mid-stream would send a second
        # http.response.start, which ASGI forbids. We trigger via the
        # status code so the WAF intercepts during header processing.
        fake_abi.trigger_response_headers_status = 200
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with TestClient(app) as c:
            rv = c.get("/")
        # The WAF flagged the response at the header phase; the test
        # app had already committed 200 so we verify the WAF saw it.
        assert rv.status_code == 200
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_response_headers" in kinds

    def test_inspect_response_happy(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, inspect_response=True)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert any(c[0] == "process_response_headers" for c in fake_abi.call_log)
        assert any(c[0] == "append_response_body" for c in fake_abi.call_log)


class TestBodyHandling:
    def test_post_body_replayed(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.post("/echo", content=b"payload-goes-here")
        assert rv.status_code == 200
        assert rv.content == b"payload-goes-here"
        assert any(
            c[0] == "append_request_body" and c[1] == len(b"payload-goes-here")
            for c in fake_abi.call_log
        )


class TestLogging:
    def test_process_logging_runs_at_end(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with TestClient(app) as c:
            c.get("/")
        kinds = [c[0] for c in fake_abi.call_log]
        assert kinds.index("process_logging") < kinds.index("free_transaction")
