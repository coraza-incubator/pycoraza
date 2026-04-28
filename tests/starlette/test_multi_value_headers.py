"""Regression: ASGI/Starlette middleware preserves multi-value headers.

Unlike WSGI, ASGI's ``scope["headers"]`` is a list of byte tuples
that natively round-trips repeated header lines — two ``Cookie``
entries arrive as two tuples. Same for ``message["headers"]`` on
``http.response.start``. The middleware MUST iterate the list rather
than collapse to a dict.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware


def _build(
    fake_abi: FakeLib,
    *,
    inspect_response: bool = False,
    response_setcookies: list[str] | None = None,
) -> Starlette:
    async def index(_request):
        # Build a Response and append raw bytes so multi-value
        # Set-Cookie reaches the wrapped send untouched. Starlette's
        # MutableHeaders ``append`` preserves duplicates.
        resp = Response("ok", media_type="text/plain")
        for cookie in response_setcookies or []:
            resp.raw_headers.append((b"set-cookie", cookie.encode("latin-1")))
        return resp

    routes = [Route("/", index)]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    return Starlette(
        routes=routes,
        middleware=[
            Middleware(
                CorazaMiddleware,
                waf=waf,
                inspect_response=inspect_response,
            )
        ],
    )


def _install_header_capture(
    fake_abi: FakeLib,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Wrap header sinks so captures survive the per-tx state cleanup
    that ``coraza_free_transaction`` performs on the fake."""
    requests: list[tuple[str, str]] = []
    responses: list[tuple[str, str]] = []

    real_req = fake_abi.coraza_add_request_header
    real_resp = fake_abi.coraza_add_response_header

    def cap_req(tx, name, name_len, value, value_len):
        nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
        vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
        requests.append((nm, vl))
        return real_req(tx, name, name_len, value, value_len)

    def cap_resp(tx, name, name_len, value, value_len):
        nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
        vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
        responses.append((nm, vl))
        return real_resp(tx, name, name_len, value, value_len)

    fake_abi.coraza_add_request_header = cap_req  # type: ignore[assignment]
    fake_abi.coraza_add_response_header = cap_resp  # type: ignore[assignment]
    return requests, responses


class TestRequestHeadersPreserved:
    def test_two_cookie_headers_pass_as_distinct_entries(
        self, fake_abi: FakeLib
    ) -> None:
        requests, _ = _install_header_capture(fake_abi)
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.get(
                "/",
                headers=[
                    ("Cookie", "a=1"),
                    ("Cookie", "b=2"),
                ],
            )
        assert rv.status_code == 200

        cookies = [v for n, v in requests if n.lower() == "cookie"]
        assert "a=1" in cookies
        assert "b=2" in cookies
        assert len(cookies) == 2

    def test_two_xff_headers_pass_as_distinct_entries(
        self, fake_abi: FakeLib
    ) -> None:
        requests, _ = _install_header_capture(fake_abi)
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.get(
                "/",
                headers=[
                    ("X-Forwarded-For", "10.0.0.1"),
                    ("X-Forwarded-For", "10.0.0.2"),
                ],
            )
        assert rv.status_code == 200

        xff = [v for n, v in requests if n.lower() == "x-forwarded-for"]
        assert xff == ["10.0.0.1", "10.0.0.2"]

    def test_single_value_host_header_intact(self, fake_abi: FakeLib) -> None:
        requests, _ = _install_header_capture(fake_abi)
        app = _build(fake_abi)
        with TestClient(app) as c:
            rv = c.get("/", headers={"Host": "waf.example"})
        assert rv.status_code == 200

        hosts = [v for n, v in requests if n.lower() == "host"]
        assert hosts == ["waf.example"]


class TestResponseHeadersPreserved:
    def test_two_set_cookies_reach_waf_as_distinct_entries(
        self, fake_abi: FakeLib
    ) -> None:
        _, responses = _install_header_capture(fake_abi)
        app = _build(
            fake_abi,
            inspect_response=True,
            response_setcookies=["a=1; Path=/", "b=2; Path=/"],
        )
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200

        cookies = [v for n, v in responses if n.lower() == "set-cookie"]
        assert "a=1; Path=/" in cookies
        assert "b=2; Path=/" in cookies
        assert len(cookies) == 2

    def test_single_value_response_header_intact(self, fake_abi: FakeLib) -> None:
        _, responses = _install_header_capture(fake_abi)
        app = _build(fake_abi, inspect_response=True)
        with TestClient(app) as c:
            rv = c.get("/")
        assert rv.status_code == 200

        names = [n.lower() for n, _ in responses]
        assert "content-type" in names
