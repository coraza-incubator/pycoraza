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


class TestExtractClientIP:
    def test_default_uses_scope_client(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with TestClient(app) as c:
            c.get("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        # Starlette TestClient uses 'testclient' as the wire client.
        assert ips and ips[0] != "203.0.113.9"

    def test_callable_extractor(self, fake_abi: FakeLib) -> None:
        def custom(scope: dict) -> str:
            for key, value in scope.get("headers", []):
                if key == b"x-real-ip":
                    return value.decode("latin-1")
            return ""

        app = _make_app(middleware_kwargs={"extract_client_ip": custom})
        with TestClient(app) as c:
            c.get("/", headers={"X-Real-IP": "198.51.100.7"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "198.51.100.7"

    def test_preset_xff_first(self, fake_abi: FakeLib) -> None:
        app = _make_app(middleware_kwargs={"extract_client_ip": "xff_first"})
        with TestClient(app) as c:
            c.get("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "203.0.113.9"

    def test_preset_cloudflare(self, fake_abi: FakeLib) -> None:
        app = _make_app(middleware_kwargs={"extract_client_ip": "cloudflare"})
        with TestClient(app) as c:
            c.get("/", headers={"CF-Connecting-IP": "198.51.100.42"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "198.51.100.42"

    def test_extractor_exception_falls_back_to_wire(self, fake_abi: FakeLib) -> None:
        def boom(_scope: dict) -> str:
            raise RuntimeError("nope")

        app = _make_app(middleware_kwargs={"extract_client_ip": boom})
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
