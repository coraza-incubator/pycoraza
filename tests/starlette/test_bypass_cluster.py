"""Regression: ASGI request-side bypass cluster (security).

C2. ``raw_path`` and ``query_string`` were decoded as latin-1 (each
    byte ↦ 1:1 codepoint). When the resulting ``str`` is re-encoded
    as UTF-8 to hand to libcoraza, every byte ≥ 0x80 expands to two
    bytes — so the WAF saw mojibake (``%C3%A4%C2%B8%C2%AD``) for
    inputs that Starlette's router decoded correctly as UTF-8
    (``%E4%B8%AD`` → ``中``). Decoding with UTF-8 and
    ``errors='surrogateescape'`` makes the byte round-trip through
    Python and reach Coraza identical to the wire bytes the client
    sent.

H1. ``/admin;.png`` matches the default ``.png`` ext-skip but
    Starlette's path converter still routes to ``/admin``. We now
    strip RFC 3986 ``;...`` parameters before invoking the skip
    predicate.
"""

from __future__ import annotations

import asyncio

import pytest
from _fake_abi import FakeLib

pytest.importorskip("starlette")
pytest.importorskip("httpx")

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware


def _build(fake_abi: FakeLib) -> Starlette:
    async def echo(_request):
        return PlainTextResponse("ok")

    routes = [Route("/{full_path:path}", echo)]
    waf = create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.BLOCK))
    return Starlette(
        routes=routes,
        middleware=[Middleware(CorazaMiddleware, waf=waf)],
    )


def _capture_uri(fake_abi: FakeLib) -> list[bytes]:
    """Capture the raw ``uri`` BYTES handed to ``coraza_process_uri``.

    The bytes are what Coraza actually evaluates — decoding them
    afterwards lets the assertion check both round-trip identity and
    the absence of latin-1-then-utf8 mojibake."""
    captured: list[bytes] = []
    real = fake_abi.coraza_process_uri

    def cap(tx, uri, method, protocol):
        b = bytes(uri) if isinstance(uri, (bytes, bytearray)) else str(uri).encode()
        captured.append(b)
        return real(tx, uri, method, protocol)

    fake_abi.coraza_process_uri = cap  # type: ignore[assignment]
    return captured


def _drive_asgi(app, scope: dict) -> None:
    """Drive an ASGI app through one request without an HTTP client.

    The TestClient URL-encodes paths before they reach the server, so
    we can't observe the latin-1 mojibake bug through it. Driving the
    app directly with a hand-built scope where ``raw_path`` carries
    non-ASCII bytes is the only way to exercise the C2 fix end-to-end
    in a unit test."""

    async def call() -> None:
        idx = [0]
        msgs_in: list[dict] = [
            {"type": "http.request", "body": b"", "more_body": False}
        ]

        async def receive() -> dict:
            m = msgs_in[idx[0]]
            idx[0] += 1
            return m

        async def send(_message: dict) -> None:
            return None

        await app(scope, receive, send)

    asyncio.run(call())


def _scope(path: str, raw_path: bytes, query_string: bytes = b"") -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": raw_path,
        "query_string": query_string,
        "http_version": "1.1",
        "scheme": "http",
        "headers": [(b"host", b"test")],
        "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 80),
        "root_path": "",
    }


class TestC2Utf8PathDecode:
    def test_utf8_raw_path_bytes_round_trip_to_waf_unchanged(
        self, fake_abi: FakeLib
    ) -> None:
        """``raw_path = b'/login\\xe4\\xb8\\xad'`` (the wire bytes of
        ``%E4%B8%AD`` after Starlette's router unescapes percent
        encoding) MUST reach Coraza as the same bytes — not as the
        latin-1-then-utf8 mojibake ``b'/login\\xc3\\xa4\\xc2\\xb8\\xc2\\xad'``
        and not with ``U+FFFD`` replacement characters."""
        uris = _capture_uri(fake_abi)
        app = _build(fake_abi)
        _drive_asgi(app, _scope("/login中", b"/login\xe4\xb8\xad"))

        assert uris, "process_uri must have been called"
        # Round-trip identity: the WAF sees what the client sent.
        assert b"/login\xe4\xb8\xad" in uris[0], (
            f"raw bytes mangled in transit; got {uris[0]!r}"
        )
        # And the latin-1 mojibake form is NOT present.
        assert b"/login\xc3\xa4\xc2\xb8\xc2\xad" not in uris[0]

    def test_utf8_query_string_bytes_round_trip(
        self, fake_abi: FakeLib
    ) -> None:
        uris = _capture_uri(fake_abi)
        app = _build(fake_abi)
        _drive_asgi(
            app,
            _scope("/search", b"/search", query_string=b"q=\xe4\xb8\xad"),
        )

        assert uris and b"?q=\xe4\xb8\xad" in uris[0], (
            f"query bytes mangled in transit; got {uris[0]!r}"
        )

    def test_no_replacement_char_in_emitted_uri(
        self, fake_abi: FakeLib
    ) -> None:
        """``surrogateescape`` MUST NOT produce ``U+FFFD`` (``�``)
        even when the input bytes are not valid UTF-8 — they are
        smuggled through as lone surrogates and re-emitted as the
        original bytes by ``_utf8`` in ``abi.py``."""
        uris = _capture_uri(fake_abi)
        app = _build(fake_abi)
        _drive_asgi(app, _scope("/x", b"/x\xff\xfe"))

        # ``\xef\xbf\xbd`` is the UTF-8 encoding of ``U+FFFD``.
        assert b"\xef\xbf\xbd" not in uris[0], (
            f"replacement char snuck into URI: {uris[0]!r}"
        )


class TestH1SkipBypassNormalization:
    def test_admin_with_path_param_is_not_skipped(
        self, fake_abi: FakeLib
    ) -> None:
        """``/admin;.png`` would match ``.png`` ext-skip without
        normalization — but Starlette's path converter ignores the
        ``;...`` segment and routes to ``/admin``."""
        app = _build(fake_abi)
        with TestClient(app) as c:
            c.get("/admin;.png")
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" in kinds

    def test_static_png_still_skipped(self, fake_abi: FakeLib) -> None:
        app = _build(fake_abi)
        with TestClient(app) as c:
            c.get("/static/foo.png")
        kinds = [c[0] for c in fake_abi.call_log]
        assert "new_transaction" not in kinds
