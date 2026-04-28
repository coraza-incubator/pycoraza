"""Flask / WSGI middleware.

Wraps a WSGI app so requests are evaluated by a Coraza WAF on the way
in and (opt-in) on the way out. Mirrors `@coraza/express` behavior:

  * `on_waf_error="block"` by default — fail closed.
  * `inspect_response=False` by default — response-side rules opt-in.
  * `skip` bypasses static assets (see `pycoraza.skip`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import IO, TYPE_CHECKING, Any
from urllib.parse import quote

from .._body import (
    BufferedBody,
    buffer_request_body,
    chunked_reader,
    decide_overflow,
    empty_replay,
    resolve_limits,
)
from ..abi import CorazaError
from ..client_ip import ClientIPArg, ClientIPExtractor, resolve_extractor
from ..skip import SkipArg, build_skip_predicate, normalize_path_for_skip
from ..types import (
    BodyLimits,
    Interruption,
    OnWAFError,
    OnWAFErrorArg,
    ProcessMode,
    RequestInfo,
)

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..waf import WAF

WSGIEnviron = dict[str, Any]
WSGIStartResponse = Callable[..., Callable[[bytes], Any]]
WSGIApp = Callable[[WSGIEnviron, WSGIStartResponse], Iterable[bytes]]

OnBlock = Callable[[Interruption, WSGIEnviron, WSGIStartResponse], Iterable[bytes] | None]


class CorazaMiddleware:
    """WSGI middleware. Plug in via `app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)`."""

    def __init__(
        self,
        app: WSGIApp,
        *,
        waf: WAF,
        on_block: OnBlock | None = None,
        inspect_response: bool = False,
        on_waf_error: OnWAFErrorArg = OnWAFError.BLOCK,
        skip: SkipArg = None,
        extract_client_ip: ClientIPArg = None,
        body_limits: BodyLimits | None = None,
    ) -> None:
        self._app = app
        self._waf = waf
        self._on_block = on_block or _default_on_block
        self._inspect_response = inspect_response
        self._on_waf_error = _normalize_on_waf_error(on_waf_error)
        self._skip = build_skip_predicate(skip)
        self._extract_client_ip: ClientIPExtractor | None = resolve_extractor(extract_client_ip)
        self._body_limits = resolve_limits(body_limits)

    def __call__(
        self, environ: WSGIEnviron, start_response: WSGIStartResponse
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        # Normalize before skip-matching: ``/admin;.png`` must NOT
        # match the ``.png`` extension skip — Werkzeug's router strips
        # ``;...`` segments at dispatch, so the request still hits the
        # ``/admin`` view. The original ``path`` is unchanged for what
        # we forward to Coraza below.
        if self._skip(method, normalize_path_for_skip(path)):
            return self._app(environ, start_response)

        request_info = _request_info_from_environ(environ, path, self._extract_client_ip)
        try:
            tx = self._waf.new_transaction()
        except CorazaError as exc:
            return self._handle_waf_error(environ, start_response, exc, request_info)

        buffered: BufferedBody | None = None
        # Phase 1+2 split-feed: read the body in chunks straight into
        # the transaction so we never need a full second copy of a
        # large upload sitting in the heap. ``buffered`` carries the
        # replay stream we'll re-attach to ``wsgi.input`` below.
        try:
            tx.process_connection(
                request_info.remote_addr or "",
                request_info.remote_port or 0,
                "",
                request_info.server_port or 0,
            )
            tx.add_request_headers(request_info.headers)
            tx.process_uri(request_info.url, request_info.method, request_info.protocol)
            if tx.process_request_headers():
                blocked = self._maybe_block(tx, environ, start_response)
                if blocked is not None:
                    return blocked

            try:
                buffered = self._read_request_body_into_tx(environ, tx)
            except CorazaError:
                raise
            except Exception as exc:
                # Slow / broken clients can drop mid-read with TimeoutError,
                # ConnectionResetError, or any framework-specific stream
                # exception. Treat as a WAF error so on_waf_error policy
                # decides — and crucially close the transaction we just
                # opened so it does not leak.
                return _finalize_now(
                    self._handle_waf_error(environ, start_response, exc, request_info), tx
                )

            decision = decide_overflow(buffered, self._body_limits)
            if decision.block_413:
                buffered.close()
                self._waf.logger.warning(
                    "body limit exceeded — blocking",
                    bytes=buffered.total_bytes,
                    limit=self._body_limits.max_total,
                    policy="block",
                )
                return _finalize_now(
                    _error_response(start_response, 413, "Payload Too Large"), tx
                )

            if buffered.exceeded_total and self._body_limits.on_overflow == "skip":
                self._waf.logger.warning(
                    "body limit exceeded — bypassing WAF",
                    bytes=buffered.total_bytes,
                    limit=self._body_limits.max_total,
                    policy="skip",
                )
                environ["wsgi.input"] = buffered.replay
                downstream = self._app(environ, start_response)
                collected: list[bytes] = []
                close_downstream = getattr(downstream, "close", None)
                try:
                    for chunk in downstream:
                        collected.append(chunk)
                finally:
                    if callable(close_downstream):
                        try:
                            close_downstream()
                        except Exception:
                            pass
                    buffered.close()
                    tx.close()
                return collected

            # WAF inspects: install the replay stream so Flask reads
            # the body we already buffered, then drive phase 2.
            environ["wsgi.input"] = buffered.replay
            if tx.process_request_body():
                blocked = self._maybe_block(tx, environ, start_response, buffered)
                if blocked is not None:
                    return blocked
            if buffered.waf_truncated:
                self._waf.logger.warning(
                    "body limit exceeded — partial WAF inspection",
                    bytes=buffered.total_bytes,
                    limit=self._body_limits.max_total,
                    policy="evaluate_partial",
                )
        except CorazaError as exc:
            if buffered is not None:
                buffered.close()
            return _finalize_now(
                self._handle_waf_error(environ, start_response, exc, request_info), tx
            )

        response_body = _capture_response(
            self._app,
            environ,
            start_response,
            tx,
            self._inspect_response,
            self._waf.mode,
            self._waf.logger,
        )
        return _finalize_now(response_body, tx, buffered)

    def _read_request_body_into_tx(
        self, environ: WSGIEnviron, tx: Transaction
    ) -> BufferedBody:
        """Stream the WSGI body into the transaction under the size budget.

        Reuses the shared spool helper so ``BodyLimits`` semantics
        (block / skip / evaluate_partial) are identical across the
        Flask, Starlette and Django adapters. Returns a ``BufferedBody``
        whose ``replay`` stream MUST be attached to ``wsgi.input``
        before the downstream app runs.
        """
        length_str = environ.get("CONTENT_LENGTH") or "0"
        try:
            length = int(length_str)
        except ValueError:
            length = 0
        stream: IO[bytes] | None = environ.get("wsgi.input")
        if length <= 0 or stream is None:
            return BufferedBody(
                replay=empty_replay(),
                total_bytes=0,
                exceeded_total=False,
                waf_truncated=False,
            )
        return buffer_request_body(
            chunked_reader(stream, content_length=length),
            limits=self._body_limits,
            append_to_tx=tx.append_request_body,
        )

    def _maybe_block(
        self,
        tx: Transaction,
        environ: WSGIEnviron,
        start_response: WSGIStartResponse,
        buffered: BufferedBody | None = None,
    ) -> Iterable[bytes] | None:
        """Honor a phase interruption when in BLOCK mode.

        Returns the WSGI iterable to send back when blocking, or
        ``None`` to signal the caller to continue evaluation. Detect
        mode (no block) returns ``None`` even on interruption — the
        WAF still sees the full request, the operator gets logs, the
        client gets the original handler's response.
        """
        intr = tx.interruption()
        if intr is None or self._waf.mode is not ProcessMode.BLOCK:
            return None
        _log_block(self._waf.logger, intr, tx.matched_rules())
        result = _call_on_block(self._on_block, intr, environ, start_response)
        if buffered is not None:
            buffered.close()
        return _finalize_now(result, tx)

    def _handle_waf_error(
        self,
        environ: WSGIEnviron,
        start_response: WSGIStartResponse,
        exc: Exception,
        request_info: RequestInfo,
    ) -> Iterable[bytes]:
        decision = _resolve_waf_error_decision(self._on_waf_error, exc, request_info)
        if decision is OnWAFError.ALLOW:
            return self._app(environ, start_response)
        return _error_response(start_response, 500, "waf error")


def _normalize_on_waf_error(arg: OnWAFErrorArg) -> OnWAFError | Callable[..., Any]:
    """Coerce the ctor argument into an enum or pass the callable through."""
    if isinstance(arg, OnWAFError):
        return arg
    if isinstance(arg, str):
        return OnWAFError(arg)
    if callable(arg):
        return arg
    raise TypeError(f"on_waf_error must be 'block', 'allow', or callable, got {type(arg)!r}")


def _resolve_waf_error_decision(
    policy: OnWAFError | Callable[..., Any],
    exc: Exception,
    request_info: RequestInfo,
) -> OnWAFError:
    """Run the user policy callable (if any) and coerce its result.

    Falls back to BLOCK if the callable raises or returns an
    unrecognized value — fail-closed posture extends to the policy
    callable itself.
    """
    if isinstance(policy, OnWAFError):
        return policy
    try:
        result = policy(exc, request_info)
    except Exception:
        return OnWAFError.BLOCK
    if isinstance(result, OnWAFError):
        return result
    if isinstance(result, str):
        try:
            return OnWAFError(result)
        except ValueError:
            return OnWAFError.BLOCK
    return OnWAFError.BLOCK


def _default_on_block(
    interruption: Interruption, _environ: WSGIEnviron, start_response: WSGIStartResponse
) -> Iterable[bytes]:
    status = interruption.status or 403
    payload = (
        f'{{"error":"blocked","rule_id":{interruption.rule_id},'
        f'"action":{_json_str(interruption.action)},'
        f'"msg":{_json_str(interruption.data)},'
        f'"data":{_json_str(interruption.data)},'
        f'"status":{status}}}'
    ).encode()
    reason = "Blocked" if status < 500 else "Error"
    start_response(
        f"{status} {reason}",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


def _log_block(logger: Any, intr: Interruption, matched: list) -> None:
    """Emit the block + the full match chain.

    Operators triaging a CRS false positive need both the disruptive
    rule (`warning`-level, the headline) and the chain of contributing
    rules (`info`-level, scrolling chain). We do this in the middleware
    instead of inside `Transaction` so users who drive the WAF directly
    can format their own log shape.
    """
    logger.warning(
        "blocked",
        rule_id=intr.rule_id,
        status=intr.status,
        action=intr.action,
        msg=intr.data,
    )
    for rule in matched:
        logger.info(
            "rule chain",
            rule_id=rule.id,
            severity=rule.severity,
            msg=rule.message,
        )


def _json_str(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def _call_on_block(
    handler: OnBlock,
    intr: Interruption,
    environ: WSGIEnviron,
    start_response: WSGIStartResponse,
) -> Iterable[bytes]:
    result = handler(intr, environ, start_response)
    if result is None:
        return _default_on_block(intr, environ, start_response)
    return result


def _request_info_from_environ(
    environ: WSGIEnviron,
    path: str,
    extract_client_ip: ClientIPExtractor | None = None,
) -> RequestInfo:
    scheme = environ.get("wsgi.url_scheme", "http")
    query = environ.get("QUERY_STRING", "")
    host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "")
    url_path = quote(path, safe="/%")
    url = f"{scheme}://{host}{url_path}"
    if query:
        url = f"{url}?{query}"

    if extract_client_ip is not None:
        try:
            remote_addr = extract_client_ip(environ) or environ.get("REMOTE_ADDR", "")
        except Exception:
            remote_addr = environ.get("REMOTE_ADDR", "")
    else:
        remote_addr = environ.get("REMOTE_ADDR", "")

    return RequestInfo(
        method=environ.get("REQUEST_METHOD", "GET"),
        url=url,
        headers=tuple(_iter_wsgi_headers(environ)),
        protocol=environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        remote_addr=remote_addr,
        remote_port=int(environ.get("REMOTE_PORT", "0") or 0),
        server_port=int(environ.get("SERVER_PORT", "0") or 0),
    )


# RFC 7230 §3.2.2 list-valued request headers: repeated lines and
# comma-separated single-line forms are semantically equivalent. WSGI
# already collapses them into a comma-joined env var, so re-splitting
# on ``,`` recovers the original entries for Coraza.
#
# Singular headers (``Content-Type``, ``Host``, ``Authorization``,
# ``User-Agent``, etc.) are deliberately NOT in this set — splitting
# them would shred legitimate values like a quoted MIME parameter
# ``application/json; charset="a, b"`` or a multipart boundary.
#
# ``Cookie`` is here because while RFC 6265 nominally bans splitting
# on ``,`` inside a single ``Cookie`` header, in practice WSGI's env
# only ever has one ``Cookie`` line per request and it's already
# semicolon-delimited; the comma split is a no-op for normal traffic
# but recovers proxy-merged duplicates if a misbehaving intermediary
# does merge them.
_LIST_VALUED_REQUEST_HEADERS = frozenset({
    "x-forwarded-for",
    "forwarded",
    "cookie",
    "accept",
    "accept-encoding",
    "accept-language",
    "via",
    "warning",
    "x-forwarded-proto",
    "x-forwarded-host",
})


def _split_list_header(value: str) -> Iterable[str]:
    """Split a comma-joined list-valued header into trimmed entries.

    Empty entries (``a,,b``) are dropped — they have no semantic
    meaning per RFC 7230 §3.2.2 and forwarding them only confuses
    rule operators.
    """
    for entry in value.split(","):
        trimmed = entry.strip()
        if trimmed:
            yield trimmed


def _iter_wsgi_headers(environ: WSGIEnviron) -> Iterable[tuple[str, str]]:
    """Yield request headers as `(name, value)` tuples for the WAF.

    Uses Werkzeug's ``EnvironHeaders`` when available — it iterates the
    canonical WSGI header set (``HTTP_*`` plus ``CONTENT_TYPE`` /
    ``CONTENT_LENGTH``) with proper title-cased names. We fall back to
    a manual loop if Werkzeug isn't installed (pure-WSGI deployments).

    Multi-value handling: PEP 3333 collapses repeated request headers
    into a single comma-joined env var. For the RFC 7230 list-valued
    set (``X-Forwarded-For``, ``Forwarded``, ``Accept`` family, ``Via``,
    ``Warning``, ``X-Forwarded-Proto/Host``, ``Cookie``) we re-split
    on ``,`` so each underlying entry reaches the WAF as its own
    ``(name, value)`` tuple — otherwise a rule keyed on an exact
    ``Content-Type``-style match against a singular header value would
    miss attacks where the merged string is e.g.
    ``application/json, text/html; <attack>``. Singular headers
    (``Content-Type``, ``Host``, ``Authorization``, ``User-Agent``,
    ``Content-Length``, ``Referer``, ``Origin``, etc.) are forwarded
    verbatim — splitting them on ``,`` would shred legitimate quoted
    parameters.

    On the response side a list of tuples emitted by ``start_response``
    already preserves duplicates (e.g. multiple ``Set-Cookie`` lines),
    so no recovery is needed there.
    """
    try:
        from werkzeug.datastructures import EnvironHeaders
    except ImportError:
        yield from _iter_wsgi_headers_fallback(environ)
        return
    for name, value in EnvironHeaders(environ):
        lowered = name.lower()
        if lowered in _LIST_VALUED_REQUEST_HEADERS and "," in value:
            for entry in _split_list_header(value):
                yield lowered, entry
        else:
            yield lowered, value


def _iter_wsgi_headers_fallback(environ: WSGIEnviron) -> Iterable[tuple[str, str]]:
    for key, value in environ.items():
        if not isinstance(value, str):
            continue
        if key.startswith("HTTP_"):
            lowered = key[5:].replace("_", "-").lower()
            if lowered in _LIST_VALUED_REQUEST_HEADERS and "," in value:
                for entry in _split_list_header(value):
                    yield lowered, entry
            else:
                yield lowered, value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            yield key.replace("_", "-").lower(), value


class _CaptureStartResponse:
    """Buffer ``start_response`` so an inspect-response block can replace it.

    When ``inspect=True`` we cannot let the downstream ``start_response``
    fire immediately: a phase-3/4 interruption must be able to replace
    the headers and status with a block response. WSGI is synchronous
    and the headers haven't hit the wire yet, so we hold them and let
    ``_capture_response`` decide once the response phases have run.

    With ``inspect=False`` we pass through to the real ``start_response``
    immediately — same behavior as before, no buffering overhead.
    """

    __slots__ = ("_inspect", "_real", "_tx", "exc_info", "headers", "status")

    def __init__(self, real: WSGIStartResponse, tx: Transaction, inspect: bool) -> None:
        self._real = real
        self._tx = tx
        self._inspect = inspect
        self.status: str = ""
        self.headers: list[tuple[str, str]] = []
        self.exc_info: object | None = None

    def __call__(
        self,
        status: str,
        response_headers: list[tuple[str, str]],
        exc_info: object | None = None,
    ) -> Callable[[bytes], Any]:
        self.status = status
        self.headers = list(response_headers)
        self.exc_info = exc_info
        if self._inspect:
            status_code = int(status.split(" ", 1)[0] or "200")
            try:
                self._tx.add_response_headers(response_headers)
                self._tx.process_response_headers(status_code)
            except CorazaError:
                pass
            # Defer the real start_response. _capture_response fires it
            # after evaluating the response body — possibly replacing
            # the headers with a block response.
            return _noop_write
        if exc_info is not None:
            return self._real(status, response_headers, exc_info)
        return self._real(status, response_headers)


def _noop_write(_data: bytes) -> Any:
    """No-op write callable returned from a buffered ``start_response``."""
    return None


def _capture_response(
    app: WSGIApp,
    environ: WSGIEnviron,
    start_response: WSGIStartResponse,
    tx: Transaction,
    inspect: bool,
    mode: ProcessMode,
    logger: Any,
) -> Iterable[bytes]:
    capture = _CaptureStartResponse(start_response, tx, inspect)
    raw = app(environ, capture)
    if not inspect:
        return raw
    buf: list[bytes] = []
    for chunk in raw:
        buf.append(chunk)
        try:
            tx.append_response_body(chunk)
        except CorazaError:
            pass

    try:
        tx.process_response_body()
    except CorazaError:
        pass

    # process_response_headers / process_response_body may each have
    # flagged an interruption. interruption() returns the cached one
    # if any phase set it; consult once.
    if mode is ProcessMode.BLOCK:
        try:
            intr = tx.interruption()
        except CorazaError:
            intr = None
        if intr is not None:
            _log_block(logger, intr, tx.matched_rules())
            return _default_on_block(intr, environ, start_response)

    if capture.status:
        if capture.exc_info is not None:
            start_response(capture.status, capture.headers, capture.exc_info)
        else:
            start_response(capture.status, capture.headers)
    return buf


def _finalize_now(
    body: Iterable[bytes], tx: Transaction, buffered: BufferedBody | None = None
) -> list[bytes]:
    """Eagerly drain `body`, then run `process_logging` + `close` before return.

    Eager finalization trades streaming for deterministic audit/log emission —
    WSGI servers are inconsistent about calling `close()` on the returned
    iterable, and a missed finalizer leaks a transaction. Coraza-node takes
    the same tradeoff in its Express/Fastify adapters.

    Closing ``buffered`` here (not earlier) lets the spool back the
    downstream app's body reads — Flask buffers the iterable in
    ``Response.iter_encoded`` before we get here, so once we're past
    that drain it's safe to release the temp file.
    """
    collected: list[bytes] = []
    close_downstream = getattr(body, "close", None)
    try:
        for chunk in body:
            collected.append(chunk)
    finally:
        if callable(close_downstream):
            try:
                close_downstream()
            except Exception:
                pass
        if buffered is not None:
            buffered.close()
        try:
            tx.process_logging()
        finally:
            tx.close()
    return collected


# 413 needs the canonical reason phrase so curl/Caddy/Nginx log it
# with the right semantics (HTTP/1.1 §6.5.11). Old default of
# "Blocked" works for 4xx but reads wrong for "too large".
_REASON_PHRASES: dict[int, str] = {
    413: "Payload Too Large",
}


def _error_response(
    start_response: WSGIStartResponse, status: int, message: str
) -> Iterable[bytes]:
    payload = message.encode("utf-8")
    reason = _REASON_PHRASES.get(status) or ("Blocked" if status < 500 else "Error")
    start_response(
        f"{status} {reason}",
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


__all__ = ["CorazaMiddleware"]
