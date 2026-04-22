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
from ..skip import SkipArg, build_skip_predicate
from ..types import Interruption, OnWAFError, ProcessMode, RequestInfo

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
        on_waf_error: OnWAFError | str = OnWAFError.BLOCK,
        skip: SkipArg = None,
    ) -> None:
        self._app = app
        self._waf = waf
        self._on_block = on_block or _default_on_block
        self._inspect_response = inspect_response
        self._on_waf_error = (
            on_waf_error if isinstance(on_waf_error, OnWAFError) else OnWAFError(on_waf_error)
        )
        self._skip = build_skip_predicate(skip)

    def __call__(
        self, environ: WSGIEnviron, start_response: WSGIStartResponse
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        if self._skip(method, path):
            return self._app(environ, start_response)

        try:
            tx = self._waf.new_transaction()
        except CorazaError:
            return self._handle_waf_error(environ, start_response)

        try:
            body = _read_wsgi_body(environ)
            interrupted = tx.process_request_bundle(
                _request_info_from_environ(environ, path), body
            )
            if interrupted:
                intr = tx.interruption()
                if intr is not None and self._waf.mode is ProcessMode.BLOCK:
                    result = _call_on_block(self._on_block, intr, environ, start_response)
                    return _finalize_now(result, tx)
        except CorazaError:
            return _finalize_now(self._handle_waf_error(environ, start_response), tx)

        response_body = _capture_response(
            self._app,
            environ,
            start_response,
            tx,
            self._inspect_response,
            self._waf.mode,
        )
        return _finalize_now(response_body, tx)

    def _handle_waf_error(
        self, environ: WSGIEnviron, start_response: WSGIStartResponse
    ) -> Iterable[bytes]:
        if self._on_waf_error is OnWAFError.ALLOW:
            return self._app(environ, start_response)
        return _error_response(start_response, 500, "waf error")


def _default_on_block(
    interruption: Interruption, _environ: WSGIEnviron, start_response: WSGIStartResponse
) -> Iterable[bytes]:
    status = interruption.status or 403
    payload = (
        f'{{"error":"blocked","rule_id":{interruption.rule_id},'
        f'"action":{_json_str(interruption.action)},'
        f'"data":{_json_str(interruption.data)}}}'
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


def _request_info_from_environ(environ: WSGIEnviron, path: str) -> RequestInfo:
    scheme = environ.get("wsgi.url_scheme", "http")
    query = environ.get("QUERY_STRING", "")
    host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "")
    url_path = quote(path, safe="/%")
    url = f"{scheme}://{host}{url_path}"
    if query:
        url = f"{url}?{query}"

    return RequestInfo(
        method=environ.get("REQUEST_METHOD", "GET"),
        url=url,
        headers=tuple(_iter_wsgi_headers(environ)),
        protocol=environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        remote_addr=environ.get("REMOTE_ADDR", ""),
        remote_port=int(environ.get("REMOTE_PORT", "0") or 0),
        server_port=int(environ.get("SERVER_PORT", "0") or 0),
    )


def _iter_wsgi_headers(environ: WSGIEnviron) -> Iterable[tuple[str, str]]:
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
