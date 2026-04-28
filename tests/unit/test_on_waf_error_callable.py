"""coraza-node #29: `on_waf_error` accepts a callable.

Exercises the callable-policy path in both the Flask (WSGI) and
Starlette (ASGI) adapters:

* callable returning "allow" -> request passes through to the app
* callable returning "block" -> request gets a 500
* callable raising an exception -> falls back to BLOCK (fail-closed)

Flask is the canonical "before-receive" adapter, so the allow path
actually proxies to the downstream app. Starlette consumes `receive`
*before* the WAF call, so an `allow` decision after the receive cannot
fall through to the app — Starlette deliberately raises CorazaError in
that case. We assert the callable is *invoked* and the response is a
non-2xx (Starlette's exception middleware turns the raise into 500).
"""

from __future__ import annotations

from typing import Any

import pytest
from _fake_abi import FakeLib

from pycoraza import OnWAFError, ProcessMode, RequestInfo, WAFConfig, create_waf

flask = pytest.importorskip("flask")
pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from pycoraza.flask import CorazaMiddleware as FlaskMW
from pycoraza.starlette import CorazaMiddleware as StarletteMW

# --------------------------------------------------------------------- #
# Flask
# --------------------------------------------------------------------- #


def _build_flask(fake_abi: FakeLib, *, on_waf_error: Any) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/")
    def index() -> str:
        return "ok"

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    app.wsgi_app = FlaskMW(app.wsgi_app, waf=waf, on_waf_error=on_waf_error)
    return app


class TestFlaskCallable:
    def test_callable_allow_passes_through(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        seen: list[tuple[Exception, RequestInfo]] = []

        def policy(exc: Exception, req: RequestInfo) -> str:
            seen.append((exc, req))
            return "allow"

        app = _build_flask(fake_abi, on_waf_error=policy)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.data == b"ok"
        assert len(seen) == 1
        exc, req = seen[0]
        assert isinstance(exc, Exception)
        assert isinstance(req, RequestInfo)
        assert req.method == "GET"

    def test_callable_block_returns_500(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> str:
            return "block"

        app = _build_flask(fake_abi, on_waf_error=policy)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500
        assert rv.data == b"waf error"

    def test_callable_that_raises_falls_back_to_block(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> str:
            raise RuntimeError("policy boom")

        app = _build_flask(fake_abi, on_waf_error=policy)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_callable_returning_garbage_falls_back_to_block(
        self, fake_abi: FakeLib
    ) -> None:
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> Any:
            return "carry-on"  # neither "block" nor "allow"

        app = _build_flask(fake_abi, on_waf_error=policy)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_string_block_still_works(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build_flask(fake_abi, on_waf_error="block")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_string_allow_still_works(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build_flask(fake_abi, on_waf_error="allow")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200

    def test_invalid_argument_type_raises(self, fake_abi: FakeLib) -> None:
        with pytest.raises(TypeError):
            _build_flask(fake_abi, on_waf_error=42)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# Starlette
# --------------------------------------------------------------------- #


def _build_starlette(fake_abi: FakeLib, *, on_waf_error: Any) -> Starlette:
    async def index(_request):
        return PlainTextResponse("ok")

    routes = [Route("/", index)]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    return Starlette(
        routes=routes,
        middleware=[Middleware(StarletteMW, waf=waf, on_waf_error=on_waf_error)],
    )


class TestStarletteCallable:
    def test_callable_block_returns_500(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> str:
            return "block"

        app = _build_starlette(fake_abi, on_waf_error=policy)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500
        assert rv.text == "waf error"

    def test_callable_invoked_with_request_info(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        seen: list[tuple[Exception, RequestInfo]] = []

        def policy(exc: Exception, req: RequestInfo) -> str:
            seen.append((exc, req))
            return "block"

        app = _build_starlette(fake_abi, on_waf_error=policy)
        with TestClient(app) as c:
            c.get("/")
        assert len(seen) == 1
        assert isinstance(seen[0][0], Exception)
        assert isinstance(seen[0][1], RequestInfo)
        assert seen[0][1].method == "GET"

    def test_callable_allow_replays_buffered_body(
        self, fake_abi: FakeLib
    ) -> None:
        # Starlette has already drained `receive` into a buffer by the
        # time the WAF is invoked. An ``allow`` decision now replays
        # the buffer through the downstream app so fail-open behaves
        # like fail-open everywhere else.
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> str:
            return "allow"

        app = _build_starlette(fake_abi, on_waf_error=policy)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200

    def test_callable_that_raises_falls_back_to_block(
        self, fake_abi: FakeLib
    ) -> None:
        fake_abi.raise_on_new_transaction = True

        def policy(_exc: Exception, _req: RequestInfo) -> str:
            raise RuntimeError("policy boom")

        app = _build_starlette(fake_abi, on_waf_error=policy)
        with TestClient(app) as c:
            rv = c.get("/")
        # Falls back to BLOCK -> 500 "waf error", NOT the policy's
        # RuntimeError leaking out of the adapter.
        assert rv.status_code == 500
        assert rv.text == "waf error"

    def test_string_block_still_works(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build_starlette(fake_abi, on_waf_error="block")
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_enum_block_still_works(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build_starlette(fake_abi, on_waf_error=OnWAFError.BLOCK)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_invalid_argument_type_raises(self, fake_abi: FakeLib) -> None:
        # Starlette's `Middleware(...)` lazy-instantiates on app start,
        # so the TypeError surfaces when the test client lifespan kicks
        # in. Construct the middleware directly to assert it cleanly.
        from pycoraza import WAFConfig as _WAFConfig
        from pycoraza import create_waf as _create
        from pycoraza.starlette import CorazaMiddleware as _MW

        async def _inner(_s, _r, _x):
            return None

        waf = _create(_WAFConfig(rules="SecRuleEngine On\n"))
        with pytest.raises(TypeError):
            _MW(_inner, waf=waf, on_waf_error=42)  # type: ignore[arg-type]


# --------------------------------------------------------------------- #
# Public re-exports
# --------------------------------------------------------------------- #


def test_waferrorpolicy_alias_is_public() -> None:
    import pycoraza

    assert hasattr(pycoraza, "WAFErrorPolicy")
    assert hasattr(pycoraza, "OnWAFErrorArg")
