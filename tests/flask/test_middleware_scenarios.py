"""End-to-end scenarios for the Flask/WSGI middleware with the fake ABI."""

from __future__ import annotations

import json

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware


def _build(
    fake_abi: FakeLib,
    *,
    mode: ProcessMode = ProcessMode.BLOCK,
    inspect_response: bool = False,
    skip=None,
    on_waf_error: str = "block",
    on_block=None,
    app_crashes: bool = False,
) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/")
    def index() -> str:
        return "ok"

    @app.route("/static/app.js")
    def static_asset() -> flask.Response:
        return flask.Response("alert(1)", mimetype="application/javascript")

    @app.route("/echo", methods=["POST"])
    def echo() -> flask.Response:
        return flask.Response(
            flask.request.get_data(), mimetype="application/octet-stream"
        )

    @app.route("/secret")
    def secret() -> flask.Response:
        return flask.Response("secret leak here", mimetype="text/plain")

    if app_crashes:
        @app.errorhandler(500)
        def five_hundred(_err: Exception) -> flask.Response:
            return flask.Response("boom", status=500)

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    app.wsgi_app = CorazaMiddleware(
        app.wsgi_app,
        waf=waf,
        inspect_response=inspect_response,
        skip=skip,
        on_waf_error=on_waf_error,
        on_block=on_block,
    )
    return app


class TestAttackBlocking:
    def test_block_mode_returns_403_json(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        app = _build(fake_abi, mode=ProcessMode.BLOCK)
        with app.test_client() as c:
            rv = c.get("/attack?q=1")
        assert rv.status_code == 403
        assert rv.headers["Content-Type"] == "application/json"
        body = json.loads(rv.data)
        assert body["error"] == "blocked"
        assert body["rule_id"] == 1001
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in kinds
        assert "free_transaction" in kinds

    def test_detect_mode_does_not_block(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        app = _build(fake_abi, mode=ProcessMode.DETECT)
        with app.test_client() as c:
            rv = c.get("/attack")
        assert rv.status_code == 404
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in kinds

    def test_custom_on_block(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"

        def on_block(intr, environ, start_response):
            start_response("418 Teapot", [("Content-Type", "text/plain")])
            return [b"nope"]

        app = _build(fake_abi, mode=ProcessMode.BLOCK, on_block=on_block)
        with app.test_client() as c:
            rv = c.get("/attack")
        assert rv.status_code == 418
        assert rv.data == b"nope"

    def test_on_block_returning_none_falls_back(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"

        def on_block(intr, environ, start_response):
            return None

        app = _build(fake_abi, mode=ProcessMode.BLOCK, on_block=on_block)
        with app.test_client() as c:
            rv = c.get("/attack")
        assert rv.status_code == 403


class TestSkip:
    def test_static_asset_bypasses(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.get("/static/app.js")
        assert rv.status_code == 200
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)

    def test_custom_callable(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, skip=lambda _method, path: path == "/")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert not any(c[0] == "new_transaction" for c in fake_abi.call_log)


class TestWAFErrors:
    def test_new_transaction_failure_blocks_by_default(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi, on_waf_error="block")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_new_transaction_failure_allow_passes_through(self, fake_abi: FakeLib) -> None:
        fake_abi.raise_on_new_transaction = True
        app = _build(fake_abi, on_waf_error="allow")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.data == b"ok"

    def test_processing_failure_blocks_by_default(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_uri")
        app = _build(fake_abi, on_waf_error="block")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 500

    def test_processing_failure_allow(self, fake_abi: FakeLib) -> None:
        fake_abi.fail_rc_for.add("process_uri")
        app = _build(fake_abi, on_waf_error="allow")
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200


class TestResponseInspection:
    def test_response_body_feeds_waf(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, mode=ProcessMode.BLOCK, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/secret")
        assert rv.status_code == 200
        assert any(c[0] == "append_response_body" for c in fake_abi.call_log)
        assert any(c[0] == "process_response_body" for c in fake_abi.call_log)

    def test_inspect_response_still_logs(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi, inspect_response=True)
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert any(c[0] == "process_response_headers" for c in fake_abi.call_log)
        assert any(c[0] == "append_response_body" for c in fake_abi.call_log)


class TestBodyHandling:
    def test_post_body_visible_to_waf(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.post("/echo", data=b"payload-data")
        assert rv.status_code == 200
        assert rv.data == b"payload-data"
        assert any(
            c[0] == "append_request_body" and c[1] == len(b"payload-data")
            for c in fake_abi.call_log
        )

    def test_body_still_readable_by_app(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            rv = c.post("/echo", data=b"some-body")
        assert rv.data == b"some-body"


class TestLogging:
    def test_process_logging_runs_at_end(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with app.test_client() as c:
            c.get("/")
        kinds = [c[0] for c in fake_abi.call_log]
        assert kinds.index("process_logging") < kinds.index("free_transaction")
