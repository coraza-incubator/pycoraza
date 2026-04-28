"""Regression: header / path bypass cluster (security).

Three distinct bypass shapes share the WSGI request-info path:

C1. WSGI collapses repeated request headers into one comma-joined
    env value (PEP 3333). For RFC 7230 list-valued headers we
    re-split on ``,`` so each entry reaches the WAF as its own
    ``(name, value)`` tuple — otherwise rules keyed on exact values
    miss merged-string attacks.

H1. ``/admin;.png`` matches the default ``.png`` ext-skip but
    Werkzeug's router still dispatches to ``/admin``. We now
    normalize away RFC 3986 ``;...`` parameters before invoking the
    skip predicate.
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware


def _build_app(fake_abi: FakeLib) -> flask.Flask:
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path: str) -> flask.Response:
        return flask.Response("ok", mimetype="text/plain")

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)
    return app


def _capture_request_headers(
    fake_abi: FakeLib,
) -> list[tuple[str, str]]:
    captured: list[tuple[str, str]] = []
    real = fake_abi.coraza_add_request_header

    def cap(tx, name, name_len, value, value_len):
        nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
        vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
        captured.append((nm, vl))
        return real(tx, name, name_len, value, value_len)

    fake_abi.coraza_add_request_header = cap  # type: ignore[assignment]
    return captured


class TestC1MultiValueHeaderSplit:
    def test_xforwarded_for_split_into_distinct_tuples(
        self, fake_abi: FakeLib
    ) -> None:
        """Two ``X-Forwarded-For`` lines collapse into one comma-joined
        env value at the WSGI boundary; we re-split for the WAF so a
        rule keyed on exact IP equality still fires on each entry."""
        requests = _capture_request_headers(fake_abi)
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
        assert xff == ["10.0.0.1", "10.0.0.2"], (
            f"WAF must see split tuples, got {xff!r}"
        )

    def test_accept_split_recovers_each_media_range(
        self, fake_abi: FakeLib
    ) -> None:
        """Splitting ``Accept`` recovers each media range so rules
        keyed on exact ``application/json`` or ``text/html`` match."""
        requests = _capture_request_headers(fake_abi)
        app = _build_app(fake_abi)
        with app.test_client() as c:
            rv = c.get(
                "/",
                headers={"Accept": "application/json, text/html"},
            )
        assert rv.status_code == 200

        accepts = [v for n, v in requests if n.lower() == "accept"]
        assert "application/json" in accepts
        assert "text/html" in accepts

    def test_singular_content_type_not_split(self, fake_abi: FakeLib) -> None:
        """``Content-Type`` is singular per RFC 7231; splitting on ``,``
        would shred legitimate values like ``multipart/form-data;
        boundary="a, b"``. Verify it passes through verbatim."""
        requests = _capture_request_headers(fake_abi)
        app = _build_app(fake_abi)
        with app.test_client() as c:
            rv = c.post(
                "/",
                data=b"x",
                content_type='multipart/form-data; boundary="a, b"',
            )
        assert rv.status_code == 200

        cts = [v for n, v in requests if n.lower() == "content-type"]
        assert cts == ['multipart/form-data; boundary="a, b"']


class TestH1SkipBypassNormalization:
    def test_admin_with_path_param_is_not_skipped(
        self, fake_abi: FakeLib
    ) -> None:
        """``/admin;.png`` would match ``.png`` ext-skip without
        normalization — but the framework router dispatches to
        ``/admin``, so the WAF MUST evaluate it."""
        app = _build_app(fake_abi)
        with app.test_client() as c:
            c.get("/admin;.png")
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds, (
            "WAF must evaluate /admin;.png; ext-skip bypass is now closed"
        )

    def test_static_png_still_skipped(self, fake_abi: FakeLib) -> None:
        """The legitimate static-asset bypass MUST keep working —
        normalization only strips ``;...``, not the ``.png`` suffix."""
        app = _build_app(fake_abi)
        with app.test_client() as c:
            c.get("/static/foo.png")
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" not in kinds

    def test_admin_plain_still_evaluated(self, fake_abi: FakeLib) -> None:
        """Sanity: a plain ``/admin`` request always reaches the WAF
        (no extension match, no prefix match in defaults)."""
        app = _build_app(fake_abi)
        with app.test_client() as c:
            c.get("/admin")
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds

    def test_path_param_in_segment_normalized(self, fake_abi: FakeLib) -> None:
        """``;...`` per-segment: ``/foo/bar;baz/qux.png`` should NOT
        skip on ``.png`` because the trailing segment is ``qux.png``
        — but ``;...`` is stripped in the middle without affecting
        the leaf extension match."""
        app = _build_app(fake_abi)
        with app.test_client() as c:
            c.get("/foo/bar;baz/qux.png")
        kinds = [c[0] for c in fake_abi.call_log]
        # qux.png suffix wins → still skipped (legitimate static).
        assert "new_transaction" not in kinds
