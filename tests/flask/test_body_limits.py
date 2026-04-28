"""Body-limits behavior for the Flask/WSGI adapter.

Covers:
  * small body (under max_in_memory) — current path, unchanged
  * medium body (above max_in_memory, below max_total) — spools
  * oversized + on_overflow="block" — 413, downstream NOT called
  * oversized + on_overflow="skip" — WAF skipped, downstream sees full body
  * oversized + on_overflow="evaluate_partial" — WAF sees prefix, downstream sees full
"""

from __future__ import annotations

import pytest
from _fake_abi import FakeLib

flask = pytest.importorskip("flask")

from pycoraza import BodyLimits, ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware

_DOWNSTREAM_HITS: list[int] = []


def _build(
    fake_abi: FakeLib,
    *,
    body_limits: BodyLimits | None = None,
    mode: ProcessMode = ProcessMode.BLOCK,
) -> flask.Flask:
    _DOWNSTREAM_HITS.clear()
    app = flask.Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/echo", methods=["POST"])
    def echo() -> flask.Response:
        data = flask.request.get_data() or b""
        _DOWNSTREAM_HITS.append(len(data))
        return flask.Response(str(len(data)), mimetype="text/plain")

    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))
    app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf, body_limits=body_limits)
    return app


class TestSmallBody:
    def test_under_max_in_memory_unchanged(self, fake_abi: FakeLib) -> None:
        app = _build(
            fake_abi,
            body_limits=BodyLimits(max_in_memory=4096, max_total=8192),
        )
        body = b"hello=world"
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 200
        assert rv.data == str(len(body)).encode()
        assert [len(body)] == _DOWNSTREAM_HITS
        # Each 1KB chunk produced one append; tiny body is one append.
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == len(body)


class TestMediumBody:
    def test_spools_when_over_in_memory(self, fake_abi: FakeLib) -> None:
        # 1KB max RAM, 64KB max total. 8KB body spills to spool, no overflow.
        app = _build(
            fake_abi,
            body_limits=BodyLimits(max_in_memory=1024, max_total=65536),
        )
        body = b"X" * 8192
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 200
        # WAF saw the full body in chunks, downstream got byte-identical.
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == len(body)
        assert [len(body)] == _DOWNSTREAM_HITS


class TestOverflowBlock:
    def test_returns_413_and_skips_downstream(self, fake_abi: FakeLib) -> None:
        app = _build(
            fake_abi,
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="block"
            ),
        )
        body = b"Z" * 4096
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 413
        # The downstream view must NOT have been called.
        assert _DOWNSTREAM_HITS == []
        # The WAF saw exactly max_total bytes — no overflow leaked into it.
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        assert sum(feeds) == 1024


class TestOverflowSkip:
    def test_bypasses_waf_and_forwards_full_body(self, fake_abi: FakeLib) -> None:
        app = _build(
            fake_abi,
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="skip"
            ),
        )
        body = b"S" * 4096
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 200
        # Downstream got the full body.
        assert [len(body)] == _DOWNSTREAM_HITS
        # process_request_body was never called for this request because
        # we bypassed the WAF on overflow.
        kinds = [c[0] for c in fake_abi.call_log]
        assert "process_request_body" not in kinds


class TestOverflowEvaluatePartial:
    def test_waf_sees_prefix_downstream_sees_full(self, fake_abi: FakeLib) -> None:
        app = _build(
            fake_abi,
            body_limits=BodyLimits(
                max_in_memory=512, max_total=1024, on_overflow="evaluate_partial"
            ),
        )
        body = b"P" * 4096
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 200
        assert [len(body)] == _DOWNSTREAM_HITS
        feeds = [c[1] for c in fake_abi.call_log if c[0] == "append_request_body"]
        # WAF saw exactly max_total bytes; the rest never reached it.
        assert sum(feeds) == 1024
        kinds = [c[0] for c in fake_abi.call_log]
        # Phase 2 still ran on the truncated prefix.
        assert "process_request_body" in kinds


class TestDefaultsFailClosed:
    def test_default_overflow_is_block(self, fake_abi: FakeLib) -> None:
        app = _build(
            fake_abi,
            body_limits=BodyLimits(max_in_memory=128, max_total=256),
        )
        body = b"D" * 1024
        with app.test_client() as c:
            rv = c.post("/echo", data=body)
        assert rv.status_code == 413
        assert _DOWNSTREAM_HITS == []
