"""`pycoraza.flask.CorazaMiddleware` — unit-level smoke with fake ABI."""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware


def _make_app(mw_kwargs: dict | None = None, mode: ProcessMode = ProcessMode.BLOCK) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/")
    def index() -> str:
        return "hi"

    @app.route("/post", methods=["POST"])
    def post() -> str:
        data = flask.request.get_data() or b""
        return f"got {len(data)}"

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf, **(mw_kwargs or {}))
    return app


class TestHappyPath:
    def test_get_passes(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        assert rv.data == b"hi"
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds
        assert "process_logging" in kinds
        assert "free_transaction" in kinds

    def test_post_body_passed_to_waf(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with app.test_client() as c:
            rv = c.post("/post", data=b"hello=world")
        assert rv.status_code == 200
        assert any(
            c[0] == "append_request_body" and c[1] == len(b"hello=world")
            for c in fake_abi.call_log
        )


class TestBuildOnly:
    def test_accepts_string_on_waf_error(self, fake_abi: FakeLib) -> None:
        app = _make_app(mw_kwargs={"on_waf_error": "allow"})
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200

    def test_skip_bool_false_runs_waf_on_static(self, fake_abi: FakeLib) -> None:
        app = _make_app(mw_kwargs={"skip": False})
        with app.test_client() as c:
            rv = c.get("/static/app.js")
        assert rv.status_code == 404
        assert any(c[0] == "new_transaction" for c in fake_abi.call_log)


class TestExtractClientIP:
    def test_default_uses_remote_addr(self, fake_abi: FakeLib) -> None:
        app = _make_app()
        with app.test_client() as c:
            c.get("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "127.0.0.1"

    def test_callable_extractor(self, fake_abi: FakeLib) -> None:
        def custom(environ: dict) -> str:
            return environ.get("HTTP_X_REAL_IP", "")

        app = _make_app(mw_kwargs={"extract_client_ip": custom})
        with app.test_client() as c:
            c.get("/", headers={"X-Real-IP": "198.51.100.7"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "198.51.100.7"

    def test_preset_xff_first(self, fake_abi: FakeLib) -> None:
        app = _make_app(mw_kwargs={"extract_client_ip": "xff_first"})
        with app.test_client() as c:
            c.get("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "203.0.113.9"

    def test_preset_cloudflare(self, fake_abi: FakeLib) -> None:
        app = _make_app(mw_kwargs={"extract_client_ip": "cloudflare"})
        with app.test_client() as c:
            c.get("/", headers={"CF-Connecting-IP": "198.51.100.42"})
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "198.51.100.42"

    def test_extractor_exception_falls_back_to_remote_addr(self, fake_abi: FakeLib) -> None:
        def boom(_environ: dict) -> str:
            raise RuntimeError("nope")

        app = _make_app(mw_kwargs={"extract_client_ip": boom})
        with app.test_client() as c:
            rv = c.get("/")
        assert rv.status_code == 200
        ips = [c[1] for c in fake_abi.call_log if c[0] == "process_connection"]
        assert ips and ips[0] == "127.0.0.1"
