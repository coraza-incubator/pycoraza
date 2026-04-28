"""Regression: WSGI/Flask middleware preserves multi-value headers.

Per PEP 3333, repeated *request* header lines collapse into a single
comma-joined env var, so the WAF sees one combined entry — that's a
WSGI-spec limitation, not something we can recover from. What we DO
guarantee:

* Single-value headers (``Host``) survive intact.
* Werkzeug-canonical names are used (``X-Forwarded-For``, not
  ``HTTP_X_FORWARDED_FOR``-derived garbage), and ``Content-Type`` /
  ``Content-Length`` are surfaced.
* On the *response* side, each ``Set-Cookie`` from
  ``start_response`` reaches the WAF as a distinct tuple — RFC 6265
  forbids combining them, and our middleware never collapses.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware


def _build_app(
    fake_abi: FakeLib,
    *,
    inspect_response: bool = False,
    response_setcookies: list[str] | None = None,
) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/", methods=["GET", "POST"])
    def index() -> flask.Response:
        resp = flask.Response("ok")
        for cookie in response_setcookies or []:
            resp.headers.add("Set-Cookie", cookie)
        return resp

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    app.wsgi_app = CorazaMiddleware(
        app.wsgi_app, waf=waf, inspect_response=inspect_response
    )
    return app


def _install_header_capture(fake_abi: FakeLib) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Wrap the fake's header sinks so we keep a record after the
    transaction is freed (the fake removes per-tx state on free)."""
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
    def test_single_value_host_header_round_trips(self, fake_abi: FakeLib) -> None:
        requests, _ = _install_header_capture(fake_abi)
        app = _build_app(fake_abi)
        with app.test_client() as c:
            rv = c.get("/", headers={"Host": "waf.example"})
        assert rv.status_code == 200

        names = [n.lower() for n, _ in requests]
        assert names.count("host") == 1
        host_value = next(v for n, v in requests if n.lower() == "host")
        assert host_value == "waf.example"

    def test_content_type_and_length_forwarded(self, fake_abi: FakeLib) -> None:
        """``EnvironHeaders`` surfaces ``Content-Type`` / ``Content-Length``
        which the previous manual env loop captured under hyphenated
        lower-case names. Confirm both still arrive at the WAF."""
        requests, _ = _install_header_capture(fake_abi)
        app = _build_app(fake_abi)
        with app.test_client() as c:
            rv = c.post(
                "/", data=b'{"x":1}', content_type="application/json"
            )
        assert rv.status_code == 200

        seen = {n.lower(): v for n, v in requests}
        assert seen.get("content-type") == "application/json"
        assert seen.get("content-length") == str(len(b'{"x":1}'))

    def test_repeated_xff_collapses_per_pep3333(self, fake_abi: FakeLib) -> None:
        """Sending two ``X-Forwarded-For`` lines through Werkzeug's
        client merges them into one comma-joined env value (PEP 3333).
        We forward whatever the env contains — verify the value is
        non-empty and contains both IPs so a downstream rule can split
        on comma. This is a WSGI limitation, not a pycoraza bug."""
        requests, _ = _install_header_capture(fake_abi)
        app = _build_app(fake_abi)
        with app.test_client() as c:
            rv = c.get(
                "/",
                headers=[
                    ("X-Forwarded-For", "10.0.0.1"),
                    ("X-Forwarded-For", "10.0.0.2"),
                ],
            )
        assert rv.status_code == 200

        xff = [v for n, v in requests if n.lower() == "x-forwarded-for"]
        assert xff, "x-forwarded-for must reach the WAF"
        joined = ", ".join(xff)
        assert "10.0.0.1" in joined and "10.0.0.2" in joined


class TestResponseHeadersPreserved:
    def test_two_set_cookies_reach_waf_as_distinct_entries(
        self, fake_abi: FakeLib
    ) -> None:
        """RFC 6265 forbids combining ``Set-Cookie`` headers. WSGI's
        ``start_response`` honours that — Flask emits one tuple per
        cookie. The middleware must not collapse them on the way to
        the WAF."""
        _, responses = _install_header_capture(fake_abi)
        app = _build_app(
            fake_abi,
            inspect_response=True,
            response_setcookies=["a=1; Path=/", "b=2; Path=/"],
        )
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200

        cookies = [v for n, v in responses if n.lower() == "set-cookie"]
        assert "a=1; Path=/" in cookies
        assert "b=2; Path=/" in cookies
        assert len(cookies) == 2

    def test_single_value_header_still_works(self, fake_abi: FakeLib) -> None:
        _, responses = _install_header_capture(fake_abi)
        app = _build_app(fake_abi, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200

        names = [n.lower() for n, _ in responses]
        assert "content-type" in names
