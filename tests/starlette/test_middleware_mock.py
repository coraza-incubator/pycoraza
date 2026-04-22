"""`pycoraza.starlette.CorazaMiddleware` — unit smoke with fake ABI."""

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

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware


def _make_app(
    *, mode: ProcessMode = ProcessMode.BLOCK, middleware_kwargs: dict | None = None
) -> Starlette:
    async def hi(_request):
        return PlainTextResponse("hi")

    async def echo(request):
        body = await request.body()
        return PlainTextResponse(body)

    routes = [Route("/", hi), Route("/echo", echo, methods=["POST"])]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    mw = [Middleware(CorazaMiddleware, waf=waf, **(middleware_kwargs or {}))]
    return Starlette(routes=routes, middleware=mw)


class TestHappyPath:
    def test_get(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.text == "hi"
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds
        assert "process_logging" in kinds

    def test_post_body_goes_through(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with TestClient(app) as c:
            rv = c.post("/echo", content=b"payload")
        assert rv.status_code == 200
        assert rv.content == b"payload"
        assert any(
            c[0] == "append_request_body" and c[1] == len(b"payload")
            for c in fake_abi.call_log
        )

    async def test_non_http_scope_passes_through(self, fake_abi: FakeLib) -> None:
        async def app(scope, receive, send):
            await send({"type": scope["type"] + ".done"})

        waf = create_waf(WAFConfig(rules="r"))
        mw = CorazaMiddleware(app, waf=waf)
        sent: list = []

        async def receive():
            return {"type": "ignored"}

        async def send(msg):
            sent.append(msg)

        await mw({"type": "websocket"}, receive, send)
        assert sent == [{"type": "websocket.done"}]
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)
