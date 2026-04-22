"""`pycoraza.fastapi` re-exports Starlette's middleware."""

from __future__ import annotations

import pytest

from _fake_abi import FakeLib


class TestReexport:
    def test_corazamiddleware_is_starlette(self) -> None:
        from pycoraza.fastapi import CorazaMiddleware as FastAPI_MW
        from pycoraza.starlette import CorazaMiddleware as Starlette_MW

        assert FastAPI_MW is Starlette_MW

    def test_onblockasync_reexported(self) -> None:
        from pycoraza.fastapi import OnBlockAsync  # noqa: F401


class TestWithFastAPI:
    def test_add_middleware_smoke(self, fake_abi: FakeLib) -> None:
        fastapi = pytest.importorskip("fastapi")
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient

        from pycoraza import ProcessMode, WAFConfig, create_waf
        from pycoraza.fastapi import CorazaMiddleware

        app = fastapi.FastAPI()

        @app.get("/")
        def root() -> dict:
            return {"ok": True}

        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
        app.add_middleware(CorazaMiddleware, waf=waf)

        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.json() == {"ok": True}

    def test_add_middleware_blocks_attack(self, fake_abi: FakeLib) -> None:
        fastapi = pytest.importorskip("fastapi")
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient

        from pycoraza import ProcessMode, WAFConfig, create_waf
        from pycoraza.fastapi import CorazaMiddleware

        fake_abi.trigger_uri_contains = "/attack"
        app = fastapi.FastAPI()

        @app.get("/attack")
        def attack() -> dict:
            return {"leak": True}

        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
        app.add_middleware(CorazaMiddleware, waf=waf)

        with TestClient(app) as c:
            rv = c.get("/attack")
        assert rv.status_code == 403
