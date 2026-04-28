"""Coverage for Flask middleware error/edge paths.

Exercises the `on_waf_error="allow"` branch, the `_handle_waf_error`
500-path, the `_read_wsgi_body` bad-Content-Length fallback, and the
response-body-inspection interruption path — all branches the happy
scenarios tests don't touch.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import OnWAFError, ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware


def _build(fake_abi: FakeLib, **kw) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/")
    def index() -> str:
        return "ok"

    @app.route("/big")
    def big() -> flask.Response:
        return flask.Response("x" * 4096, mimetype="text/plain")

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=kw.pop("mode", ProcessMode.BLOCK)))
    app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf, **kw)
    return app


class TestWAFErrorAllow:
    def test_new_transaction_failure_allows_request(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi, on_waf_error=OnWAFError.ALLOW)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.data == b"ok"

    def test_new_transaction_failure_blocks_by_default(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500
        assert rv.data == b"waf error"

    def test_process_uri_failure_blocks(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_uri")
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500


class TestContentLength:
    def test_invalid_content_length_header_tolerated(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.get("/", headers={"Content-Length": "not-a-number"})
        assert rv.status_code == 200

    def test_zero_content_length_treated_as_no_body(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.get("/", headers={"Content-Length": "0"})
        assert rv.status_code == 200
        kinds = [c[0] for c in fake_abi.call_log]
        assert "append_request_body" not in kinds


class TestInspectResponse:
    def test_inspect_response_body_interrupts(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_response_body_contains = b"x"
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/big")
        assert rv.status_code == 403
        assert b"blocked" in rv.data

    def test_inspect_response_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_body")
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/big")
        assert rv.status_code == 200

    def test_inspect_response_append_body_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("append_response_body")
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/big")
        assert rv.status_code == 200

    def test_inspect_response_headers_error_swallowed(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_response_headers")
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200


class TestStringHelpers:
    def test_json_escape_handles_specials(self, fake_abi: FakeLib) -> None:
        from pycoraza.flask import _json_str

        assert _json_str('a"b') == r'"a\"b"'
        assert _json_str("a\\b") == r'"a\\b"'
        assert _json_str("a\nb") == r'"a\nb"'


class _BrokenStream:
    """``wsgi.input`` that raises mid-read.

    Mirrors what gunicorn's stream raises when a slow client drops
    the connection between the request line and the body.
    """

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def read(self, _length: int) -> bytes:
        raise self._exc

    def tell(self) -> int:  # werkzeug's EnvironBuilder probes this
        return 0

    def seek(self, *_a, **_kw) -> int:
        return 0


class TestBodyReadFailure:
    def _drive(self, app, on_waf_error):
        # Bypass werkzeug's test client so we control wsgi.input
        # directly. The middleware only ever interacts with environ —
        # no need for a real HTTP path through the client.
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "localhost",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "REMOTE_ADDR": "127.0.0.1",
            "REMOTE_PORT": "12345",
            "CONTENT_LENGTH": "16",
            "CONTENT_TYPE": "application/octet-stream",
            "wsgi.input": _BrokenStream(TimeoutError("slow client")),
        }
        captured: dict = {}

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = headers
            return lambda _data: None

        body_chunks = list(app.wsgi_app(environ, start_response))
        return captured, b"".join(body_chunks)

    def test_body_read_timeout_routes_through_on_waf_error(
        self, fake_abi: FakeLib
    ) -> None:
        # B1: a stream.read() exception used to escape uncaught and
        # leak the open transaction. Now it routes through
        # _handle_waf_error so on_waf_error="block" yields a 500
        # response and the transaction is finalized.
        app = _build(fake_abi, on_waf_error=OnWAFError.BLOCK)
        captured, body = self._drive(app, OnWAFError.BLOCK)
        assert captured["status"].startswith("500")
        assert body == b"waf error"
        # Verify the transaction was closed deterministically.
        kinds = [c[0] for c in fake_abi.call_log]
        assert "free_transaction" in kinds

    def test_body_read_failure_with_allow_passes_through(
        self, fake_abi: FakeLib
    ) -> None:
        # When on_waf_error="allow", the broken-body request is still
        # forwarded downstream (fail-open posture). Downstream Flask
        # reads from the broken stream itself, but we only assert the
        # transaction was finalized — Flask's body-read failure mode
        # is not the WAF's concern.
        app = _build(fake_abi, on_waf_error=OnWAFError.ALLOW)
        try:
            self._drive(app, OnWAFError.ALLOW)
        except TimeoutError:
            # Flask's downstream may re-raise; that's fine.
            pass
        kinds = [c[0] for c in fake_abi.call_log]
        assert "free_transaction" in kinds
