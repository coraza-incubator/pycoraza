"""Flask / WSGI middleware.

Wraps a WSGI app so requests are evaluated by a Coraza WAF on the way
in and (opt-in) on the way out. Mirrors `@coraza/express` behavior:

  * `on_waf_error="block"` by default — fail closed.
  * `inspect_response=False` by default — response-side rules opt-in.
  * `skip` bypasses static assets (see `pycoraza.skip`).
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ..abi import CorazaError
from ..client_ip import ClientIPArg, ClientIPExtractor, resolve_extractor
from ..skip import SkipArg, build_skip_predicate
from ..types import Interruption, OnWAFError, OnWAFErrorArg, ProcessMode, RequestInfo

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
    ) -> None:
        self._app = app
        self._waf = waf
        self._on_block = on_block or _default_on_block
        self._inspect_response = inspect_response
        self._on_waf_error = _normalize_on_waf_error(on_waf_error)
        self._skip = build_skip_predicate(skip)
        self._extract_client_ip: ClientIPExtractor | None = resolve_extractor(extract_client_ip)

    def __call__(
        self, environ: WSGIEnviron, start_response: WSGIStartResponse
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        if self._skip(method, path):
            return self._app(environ, start_response)

        request_info = _request_info_from_environ(environ, path, self._extract_client_ip)
        try:
            tx = self._waf.new_transaction()
        except CorazaError as exc:
            return self._handle_waf_error(environ, start_response, exc, request_info)

        try:
            body = _read_wsgi_body(environ)
            interrupted = tx.process_request_bundle(request_info, body)
            if interrupted:
                intr = tx.interruption()
                if intr is not None and self._waf.mode is ProcessMode.BLOCK:
                    _log_block(self._waf.logger, intr, tx.matched_rules())
                    result = _call_on_block(self._on_block, intr, environ, start_response)
                    return _finalize_now(result, tx)
        except CorazaError as exc:
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
        return _finalize_now(response_body, tx)

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


def _read_wsgi_body(environ: WSGIEnviron) -> bytes | None:
    length_str = environ.get("CONTENT_LENGTH") or "0"
    try:
        length = int(length_str)
    except ValueError:
        length = 0
    if length <= 0:
        return None
    stream = environ.get("wsgi.input")
    if stream is None:
        return None
    data = stream.read(length)
    environ["wsgi.input"] = io.BytesIO(data)
    return data


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


def _iter_wsgi_headers(environ: WSGIEnviron) -> Iterable[tuple[str, str]]:
    """Yield request headers as `(name, value)` tuples for the WAF.

    Uses Werkzeug's ``EnvironHeaders`` when available — it iterates the
    canonical WSGI header set (``HTTP_*`` plus ``CONTENT_TYPE`` /
    ``CONTENT_LENGTH``) with proper title-cased names. We fall back to
    a manual loop if Werkzeug isn't installed (pure-WSGI deployments).

    Note on multi-value headers: PEP 3333 collapses repeated request
    headers into a single comma-joined env var, so by the time the WAF
    sees them they are already merged. This is a WSGI-spec limitation,
    not something we can recover from on the request side. The shape
    remains ``Iterable[tuple[str, str]]`` so duplicate entries are
    forwarded as distinct tuples whenever the underlying source does
    preserve them — and the response side (a list of tuples emitted by
    ``start_response``) does, e.g. for multiple ``Set-Cookie`` headers.
    """
    try:
        from werkzeug.datastructures import EnvironHeaders
    except ImportError:
        yield from _iter_wsgi_headers_fallback(environ)
        return
    for name, value in EnvironHeaders(environ):
        yield name.lower(), value


def _iter_wsgi_headers_fallback(environ: WSGIEnviron) -> Iterable[tuple[str, str]]:
    for key, value in environ.items():
        if not isinstance(value, str):
            continue
        if key.startswith("HTTP_"):
            yield key[5:].replace("_", "-").lower(), value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            yield key.replace("_", "-").lower(), value


class _CaptureStartResponse:
    __slots__ = ("_inspect", "_real", "_tx", "headers", "status")

    def __init__(self, real: WSGIStartResponse, tx: Transaction, inspect: bool) -> None:
        self._real = real
        self._tx = tx
        self._inspect = inspect
        self.status: str = ""
        self.headers: list[tuple[str, str]] = []

    def __call__(
        self,
        status: str,
        response_headers: list[tuple[str, str]],
        exc_info: object | None = None,
    ) -> Callable[[bytes], Any]:
        self.status = status
        self.headers = list(response_headers)
        if self._inspect:
            status_code = int(status.split(" ", 1)[0] or "200")
            try:
                self._tx.add_response_headers(response_headers)
                self._tx.process_response_headers(status_code)
            except CorazaError:
                pass
        if exc_info is not None:
            return self._real(status, response_headers, exc_info)
        return self._real(status, response_headers)


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
        if tx.process_response_body() and mode is ProcessMode.BLOCK:
            intr = tx.interruption()
            if intr is not None:
                _log_block(logger, intr, tx.matched_rules())
                return _default_on_block(intr, environ, start_response)
    except CorazaError:
        pass
    return buf


def _finalize_now(body: Iterable[bytes], tx: Transaction) -> list[bytes]:
    """Eagerly drain `body`, then run `process_logging` + `close` before return.

    Eager finalization trades streaming for deterministic audit/log emission —
    WSGI servers are inconsistent about calling `close()` on the returned
    iterable, and a missed finalizer leaks a transaction. Coraza-node takes
    the same tradeoff in its Express/Fastify adapters.
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
        try:
            tx.process_logging()
        finally:
            tx.close()
    return collected


def _error_response(
    start_response: WSGIStartResponse, status: int, message: str
) -> Iterable[bytes]:
    payload = message.encode("utf-8")
    reason = "Blocked" if status < 500 else "Error"
    start_response(
        f"{status} {reason}",
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


__all__ = ["CorazaMiddleware"]
