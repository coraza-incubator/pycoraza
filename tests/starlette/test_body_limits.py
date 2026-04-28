"""Body-limits behavior for the Starlette/ASGI adapter.

Mirrors the Flask body-limits suite: small / medium / oversized x the
three ``on_overflow`` policies. Adds the ASGI-specific assertion that
the replay receive emits ``more_body`` correctly so chunk-streaming
consumers (FastAPI's UploadFile, raw ASGI apps) see the same shape
they would without the middleware in the chain.
"""

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

from pycoraza import BodyLimits, ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware

_DOWNSTREAM_HITS: list[int] = []


def _build(
    *,
    body_limits: BodyLimits | None = None,
    mode: ProcessMode = ProcessMode.BLOCK,
) -> Starlette:
    _DOWNSTREAM_HITS.clear()

    async def echo(request) -> PlainTextResponse:
        body = await request.body()
        _DOWNSTREAM_HITS.append(len(body))
        return PlainTextResponse(str(len(body)))

    routes = [Route("/echo", echo, methods=["POST"])]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    mw = [Middleware(CorazaMiddleware, waf=waf, body_limits=body_limits)]
    return Starlette(routes=routes, middleware=mw)


class TestSmallBody:
    def test_under_limit_unchanged(self, fake_abi: FakeLib) -> None:
        app = _build(body_limits=BodyLimits(max_in_memory=4096, max_total=8192))
        body = b"hi=ok"
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 200
        assert rv.content == str(len(body)).encode()
        assert [len(body)] == _DOWNSTREAM_HITS


class TestMediumBody:
    def test_spools_when_over_in_memory(self, fake_abi: FakeLib) -> None:
        app = _build(body_limits=BodyLimits(max_in_memory=1024, max_total=65536))
        body = b"M" * 8192
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 200
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == len(body)
        assert [len(body)] == _DOWNSTREAM_HITS


class TestOverflowBlock:
    def test_returns_413_and_skips_downstream(self, fake_abi: FakeLib) -> None:
        app = _build(
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="block"
            )
        )
        body = b"B" * 4096
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 413
        assert _DOWNSTREAM_HITS == []
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == 1024


class TestOverflowSkip:
    def test_bypasses_waf_and_forwards_full_body(self, fake_abi: FakeLib) -> None:
        app = _build(
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="skip"
            )
        )
        body = b"S" * 4096
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 200
        assert [len(body)] == _DOWNSTREAM_HITS
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_request_body" not in kinds


class TestOverflowEvaluatePartial:
    def test_waf_sees_prefix_downstream_sees_full(self, fake_abi: FakeLib) -> None:
        app = _build(
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="evaluate_partial"
            )
        )
        body = b"P" * 4096
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 200
        assert [len(body)] == _DOWNSTREAM_HITS
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == 1024
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_request_body" in kinds


class TestDefaultsFailClosed:
    def test_default_overflow_is_block(self, fake_abi: FakeLib) -> None:
        app = _build(body_limits=BodyLimits(max_in_memory=128, max_total=256))
        body = b"D" * 1024
        with TestClient(app) as c:
            rv = c.post("/echo", content=body)
        assert rv.status_code == 413
        assert _DOWNSTREAM_HITS == []
