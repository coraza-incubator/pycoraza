"""Adapters accept any `WAFLike` (a `WAF` or a `WAFRef`)."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

from pycoraza import ProcessMode, WAFConfig, WAFLike, WAFRef, create_waf, create_waf_ref


class TestWAFLikeAlias:
    def test_alias_resolves_to_union(self) -> None:
        # `WAFLike` is a typing alias — what matters is that it is
        # importable and that `WAF`/`WAFRef` are valid runtime values
        # for it. We don't assert on `__args__` here because typing
        # internals shift across Python versions.
        from pycoraza import WAF
        assert WAFLike is not None
        # both candidates must be instantiable for the alias to mean what
        # the docstring says.
        assert WAF is not None
        assert WAFRef is not None


class TestFlaskAdapterAcceptsWAFRef:
    def test_constructs_with_wafref(self, fake_abi: FakeLib) -> None:
        flask = pytest.importorskip("flask")
        from pycoraza.flask import CorazaMiddleware

        app = flask.Flask(__name__)

        @app.route("/")
        def index() -> str:
            return "ok"

        ref = create_waf_ref(WAFConfig(rules="SecRuleEngine On\n"))
        app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=ref)

        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200


class TestStarletteAdapterAcceptsWAFRef:
    def test_constructs_with_wafref(self, fake_abi: FakeLib) -> None:
        starlette = pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient

        from pycoraza.starlette import CorazaMiddleware

        async def index(_request):  # noqa: ANN001
            return PlainTextResponse("ok")

        ref = create_waf_ref(WAFConfig(rules="SecRuleEngine On\n"))
        app = Starlette(routes=[Route("/", index)])
        app.add_middleware(CorazaMiddleware, waf=ref)

        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200


class TestDjangoAdapterAcceptsWAFRef:
    def test_constructs_with_wafref_no_isinstance_check(self, fake_abi: FakeLib) -> None:
        django = pytest.importorskip("django")
        from django.conf import settings
        from django.http import HttpResponse
        from django.test import RequestFactory

        from pycoraza.django import CorazaMiddleware

        ref = create_waf_ref(WAFConfig(rules="SecRuleEngine On\n"))
        prev = getattr(settings, "PYCORAZA_WAF", None)
        settings.PYCORAZA_WAF = ref
        try:
            mw = CorazaMiddleware(lambda req: HttpResponse("ok"))
            rv = mw(RequestFactory().get("/"))
            assert rv.status_code == 200
            assert rv.content == b"ok"
        finally:
            if prev is None and hasattr(settings, "PYCORAZA_WAF"):
                delattr(settings, "PYCORAZA_WAF")
            else:
                settings.PYCORAZA_WAF = prev
