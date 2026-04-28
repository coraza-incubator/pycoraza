"""Coverage for Starlette middleware error/edge paths."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from pycoraza import OnWAFError, ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware


def _build(fake_abi: FakeLib, **kw) -> Starlette:
    async def index(_request):
        return PlainTextResponse("ok")

    async def big(_request):
        return PlainTextResponse("x" * 4096)

    routes = [Route("/", index), Route("/big", big)]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=kw.pop("mode", ProcessMode.BLOCK)))
    return Starlette(routes=routes, middleware=[Middleware(CorazaMiddleware, waf=waf, **kw)])


class TestWAFError:
    def test_new_transaction_failure_blocks_500(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500
        assert rv.text == "waf error"


class TestNonHTTP:
    def test_non_http_scope_passes_through(self, fake_abi: FakeLib) -> None:
        import asyncio

        from pycoraza.starlette import CorazaMiddleware as MW
        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n"))

        captured = []

        async def inner(scope, receive, send):
            captured.append(scope["type"])

        async def noop_receive():
            return {"type": "lifespan.startup"}

        async def noop_send(_m):
            return None

        async def drive():
            mw = MW(inner, waf=waf)
            await mw({"type": "lifespan"}, noop_receive, noop_send)

        asyncio.run(drive())
        assert captured == ["lifespan"]


class TestInspectResponse:
    def test_inspect_headers_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_headers")
        app = _build(fake_abi, inspect_response=True, mode=ProcessMode.BLOCK)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200

    def test_inspect_body_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_body")
        app = _build(fake_abi, inspect_response=True, mode=ProcessMode.BLOCK)
        with TestClient(app) as c:
            rv = c.get("/big")
        assert rv.status_code == 200

    def test_inspect_append_body_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("append_response_body")
        app = _build(fake_abi, inspect_response=True, mode=ProcessMode.BLOCK)
        with TestClient(app) as c:
            rv = c.get("/big")
        assert rv.status_code == 200


class TestSendWrapperEdges:
    def test_lifespan_scope_not_wrapped(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, inspect_response=True)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200

    def test_no_inspect_still_marks_response_started(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, inspect_response=False)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200


class TestOnWAFErrorAllow:
    def test_allow_replays_buffered_body_to_downstream(self, fake_abi: FakeLib) -> None:
        # The receive channel was drained into a buffer before the WAF
        # ran. When ``on_waf_error="allow"`` resolves we replay the
        # buffered body to the downstream app via _replay_receive so
        # allow-on-error is now actually fail-open instead of erroring
        # with "cannot allow-fall-through after middleware consumed
        # receive".
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi, on_waf_error=OnWAFError.ALLOW)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.text == "ok"

    def test_allow_replays_post_body(self, fake_abi: FakeLib) -> None:
        async def echo(request):
            data = await request.body()
            return PlainTextResponse(data.decode() or "empty")

        fake_abi.raise_on_new_transaction = True
        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
        app = Starlette(
            routes=[Route("/echo", echo, methods=["POST"])],
            middleware=[
                Middleware(CorazaMiddleware, waf=waf, on_waf_error=OnWAFError.ALLOW),
            ],
        )
        with TestClient(app) as c:
            rv = c.post("/echo", content=b"replayed-body")
        assert rv.status_code == 200
        assert rv.text == "replayed-body"
