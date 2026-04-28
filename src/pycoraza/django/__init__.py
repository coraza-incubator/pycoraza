"""Django middleware for pycoraza.

Settings:
    PYCORAZA_WAF                # required: a WAF instance
    PYCORAZA_ON_BLOCK           # callable(intr, request) -> HttpResponse
    PYCORAZA_INSPECT_RESPONSE   # bool, default False
    PYCORAZA_ON_WAF_ERROR       # "block" (default) | "allow"
    PYCORAZA_SKIP               # SkipArg
    PYCORAZA_BODY_LIMITS        # BodyLimits, default 1MB / 32MB / block

Supports Django 4.2+ / 5.x. WSGI and ASGI (sync-compatible).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .._body import (
    BufferedBody,
    buffer_request_body,
    chunked_reader,
    empty_replay,
    resolve_limits,
)
from ..abi import CorazaError
from ..skip import build_skip_predicate, normalize_path_for_skip
from ..types import Interruption, OnWAFError, ProcessMode, RequestInfo, WAFLike

try:
    from django.conf import settings
    from django.core.exceptions import MiddlewareNotUsed
    from django.http import HttpRequest, HttpResponse, JsonResponse
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "pycoraza.django requires Django — install with `pip install pycoraza[django]`"
    ) from exc


OnBlock = Callable[[Interruption, HttpRequest], HttpResponse]


# RFC 7230 §3.2.2 list-valued request headers — see flask/__init__.py
# for the rationale. Same set, same justification: rules keyed on the
# exact ``Content-Type``-style value miss attacks when a proxy merges
# repeated headers into one comma-joined env value.
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


def _split_list_header(value: str):
    for entry in value.split(","):
        trimmed = entry.strip()
        if trimmed:
            yield trimmed


class CorazaMiddleware:
    """Django middleware for Coraza WAF.

    Install via settings.MIDDLEWARE:

        MIDDLEWARE = [
            "pycoraza.django.CorazaMiddleware",
            ...
        ]

    Place early in the list so attacks are blocked before downstream
    middleware (auth, CSRF, sessions) consume the request.
    """

    sync_capable = True
    async_capable = False

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        waf: WAFLike | None = getattr(settings, "PYCORAZA_WAF", None)
        if waf is None:
            raise MiddlewareNotUsed(
                "pycoraza.django.CorazaMiddleware: settings.PYCORAZA_WAF is not set; "
                "set it to a WAF instance created via pycoraza.create_waf() "
                "(or a WAFRef wrapping one)."
            )

        self._get_response = get_response
        self._waf = waf
        self._on_block: OnBlock = getattr(settings, "PYCORAZA_ON_BLOCK", _default_on_block)
        self._inspect_response: bool = bool(
            getattr(settings, "PYCORAZA_INSPECT_RESPONSE", False)
        )
        on_err = getattr(settings, "PYCORAZA_ON_WAF_ERROR", OnWAFError.BLOCK)
        self._on_waf_error = (
            on_err if isinstance(on_err, OnWAFError) else OnWAFError(on_err)
        )
        self._skip = build_skip_predicate(getattr(settings, "PYCORAZA_SKIP", None))
        self._body_limits = resolve_limits(getattr(settings, "PYCORAZA_BODY_LIMITS", None))

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Normalize before skip-matching: ``/admin;.png`` must NOT
        # match the ``.png`` extension skip — Django's URL resolver
        # ignores the ``;...`` segment when dispatching, so the
        # request still hits the ``/admin`` view.
        skip_path = normalize_path_for_skip(request.path or "")
        if self._skip(request.method or "GET", skip_path):
            return self._get_response(request)

        try:
            tx = self._waf.new_transaction()
        except CorazaError:
            return self._handle_waf_error(request)

        request_info = _request_info_from_django(request)
        buffered: BufferedBody | None = None
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
                blocked = self._maybe_block(tx, request)
                if blocked is not None:
                    _finalize(tx)
                    return blocked

            buffered = self._read_request_body_into_tx(request, tx)

            if buffered.exceeded_total:
                policy = self._body_limits.on_overflow
                if policy == "block":
                    self._waf.logger.warning(
                        "body limit exceeded — blocking",
                        bytes=buffered.total_bytes,
                        limit=self._body_limits.max_total,
                        policy="block",
                    )
                    buffered.close()
                    _finalize(tx)
                    return HttpResponse(
                        "Payload Too Large",
                        status=413,
                        content_type="text/plain; charset=utf-8",
                    )
                if policy == "skip":
                    self._waf.logger.warning(
                        "body limit exceeded — bypassing WAF",
                        bytes=buffered.total_bytes,
                        limit=self._body_limits.max_total,
                        policy="skip",
                    )
                    _restore_django_body(request, buffered)
                    buffered.close()
                    tx.close()
                    return self._get_response(request)
                # evaluate_partial: WAF saw a prefix; downstream gets full body.
                self._waf.logger.warning(
                    "body limit exceeded — partial WAF inspection",
                    bytes=buffered.total_bytes,
                    limit=self._body_limits.max_total,
                    policy="evaluate_partial",
                )

            if tx.process_request_body():
                blocked = self._maybe_block(tx, request)
                if blocked is not None:
                    buffered.close()
                    _finalize(tx)
                    return blocked
        except CorazaError:
            if buffered is not None:
                buffered.close()
            _finalize(tx)
            return self._handle_waf_error(request)

        # Make the body Django expects (request.body / POST / FILES) read
        # from the buffered copy — the original stream is drained.
        _restore_django_body(request, buffered)

        try:
            response = self._get_response(request)
        except BaseException:
            buffered.close()
            _finalize(tx)
            raise

        if self._inspect_response:
            blocked = _inspect_response(tx, response)
            if blocked is not None and self._waf.mode is ProcessMode.BLOCK:
                _finalize(tx)
                return self._on_block(blocked, request)

        buffered.close()
        _finalize(tx)
        return response

    def _read_request_body_into_tx(
        self, request: HttpRequest, tx: Any
    ) -> BufferedBody:
        """Stream the Django body into the transaction under the size budget.

        Reads from ``request`` directly (which is the WSGI input stream
        wrapped by ``LimitedStream``) so we never trigger Django's
        full-body cache before the WAF has seen the bytes. The
        ``buffered`` we return must be re-attached via
        ``_restore_django_body`` so views can still call ``.body``,
        ``request.POST``, etc. without surprising EOF.
        """
        raw_len = (request.META.get("CONTENT_LENGTH") or "").strip()
        try:
            length = int(raw_len)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return BufferedBody(
                replay=empty_replay(),
                total_bytes=0,
                exceeded_total=False,
                waf_truncated=False,
            )
        # ``request`` itself satisfies the read protocol (Django wraps
        # ``wsgi.input`` in a ``LimitedStream``). Reading from it before
        # ``request.body`` is touched keeps the byte-stream shape Coraza
        # sees identical to what arrived on the wire.
        return buffer_request_body(
            chunked_reader(request, content_length=length),
            limits=self._body_limits,
            append_to_tx=tx.append_request_body,
        )

    def _maybe_block(self, tx: Any, request: HttpRequest) -> HttpResponse | None:
        """Honor a phase interruption when in BLOCK mode.

        Returns the HttpResponse the user gets back (or a custom one
        from ``PYCORAZA_ON_BLOCK``), or ``None`` to signal continuation.
        Detect mode never blocks — the WAF logs the match and the
        request runs through.
        """
        intr = tx.interruption()
        if intr is None or self._waf.mode is not ProcessMode.BLOCK:
            return None
        try:
            return self._on_block(intr, request)
        except Exception:
            # Custom on_block must not abort fail-closed posture; if it
            # explodes we still return a 403 so the attacker can't slip
            # through on a NoneType.
            return _default_on_block(intr, request)

    def _handle_waf_error(self, request: HttpRequest) -> HttpResponse:
        if self._on_waf_error is OnWAFError.ALLOW:
            return self._get_response(request)
        return HttpResponse("waf error", status=500, content_type="text/plain; charset=utf-8")


def _default_on_block(intr: Interruption, _request: HttpRequest) -> HttpResponse:
    status = intr.status or 403
    return JsonResponse(
        {
            "error": "blocked",
            "rule_id": intr.rule_id,
            "action": intr.action,
            "data": intr.data,
        },
        status=status,
    )


def _restore_django_body(request: HttpRequest, buffered: BufferedBody) -> None:
    """Pre-populate Django's body cache from ``buffered``.

    Django reads ``request._body`` lazily the first time you touch
    ``request.body`` / ``request.POST`` / ``request.FILES``. Because
    we already drained ``wsgi.input`` into the spool, that lazy read
    would either return empty (after we consumed the stream) or block
    on a closed pipe. Setting ``_body`` ourselves makes the rest of
    the request lifecycle behave exactly as if we'd never touched it.

    We materialize the bytes off the spool here — Django stores the
    body as ``bytes`` internally so we can't hand it the file
    directly. For requests above ``max_in_memory`` this is the one
    place a second copy lives, but only for as long as the view's
    request object is alive (released at end of response).
    """
    try:
        buffered.replay.seek(0)
        data = buffered.replay.read()
    except Exception:
        data = b""
    # Django's HttpRequest exposes ``_body`` as the documented cache
    # for already-parsed request bodies (see django/http/request.py).
    # Setting it here is the supported way to short-circuit a re-read.
    request._body = data
    # POST/FILES rebuild from `_body`, not from the input stream, so
    # this is enough for FormData and MultiPart parsing post-WAF.
    if hasattr(request, "_post"):
        try:
            del request._post
        except AttributeError:
            pass
    if hasattr(request, "_files"):
        try:
            del request._files
        except AttributeError:
            pass


def _request_info_from_django(request: HttpRequest) -> RequestInfo:
    # wsgiref synthesizes CONTENT_TYPE='text/plain' on bodyless GETs
    # because email.Message's default content type is text/plain. That
    # synthetic value, forwarded to Coraza, fires CRS 920420 at
    # paranoia>=2 and 403s every health probe.
    #
    # Conservative narrow strip: only drop CONTENT_TYPE if it's the
    # *exact* wsgiref default ("text/plain") AND the request carries
    # no body. Any other CT value — including wire-supplied "text/plain"
    # — is forwarded so CRS rules can evaluate. CONTENT_LENGTH gets
    # the same treatment when blank/zero (wsgiref leaves an empty
    # string, real clients send a number).
    raw_len = (request.META.get("CONTENT_LENGTH") or "").strip()
    try:
        has_body = int(raw_len) > 0
    except (TypeError, ValueError):
        has_body = False

    # Re-split RFC 7230 list-valued headers: Django's META collapses
    # repeated request headers into a comma-joined string (same WSGI
    # limitation as Flask), so we recover the originals before
    # forwarding to Coraza. Singular headers pass through verbatim.
    headers: list[tuple[str, str]] = []
    for key, value in request.META.items():
        if not isinstance(value, str):
            continue
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").lower()
            if name in _LIST_VALUED_REQUEST_HEADERS and "," in value:
                for entry in _split_list_header(value):
                    headers.append((name, entry))
            else:
                headers.append((name, value))
        elif key == "CONTENT_TYPE" and value:
            if not has_body and value == "text/plain":
                continue  # wsgiref synthetic default — drop
            headers.append(("content-type", value))
        elif key == "CONTENT_LENGTH" and value and has_body:
            headers.append(("content-length", value))

    remote_addr = request.META.get("REMOTE_ADDR", "") or ""
    remote_port = _safe_int(request.META.get("REMOTE_PORT"))
    server_port = _safe_int(request.META.get("SERVER_PORT"))
    protocol = request.META.get("SERVER_PROTOCOL", "HTTP/1.1") or "HTTP/1.1"

    return RequestInfo(
        method=request.method or "GET",
        url=request.build_absolute_uri(),
        headers=tuple(headers),
        protocol=protocol,
        remote_addr=remote_addr,
        remote_port=remote_port,
        server_port=server_port,
    )


def _safe_int(value: Any) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _inspect_response(tx: Any, response: HttpResponse) -> Interruption | None:
    """Drive phase-3/4 over the buffered Django response.

    Returns the interruption when a response-side rule fires, or
    ``None`` otherwise. Callers use that to decide whether to swap in
    a block response (BLOCK mode) or just record the match (DETECT).
    """
    status = int(getattr(response, "status_code", 200))
    try:
        headers = [(str(k), str(v)) for k, v in response.items()]
    except Exception:
        headers = []
    try:
        tx.add_response_headers(headers)
        tx.process_response_headers(status)
    except CorazaError:
        return None

    body = getattr(response, "content", b"") or b""
    if not isinstance(body, (bytes, bytearray)):
        try:
            return tx.interruption()
        except CorazaError:
            return None
    if body:
        try:
            tx.append_response_body(bytes(body))
        except CorazaError:
            return None
    try:
        tx.process_response_body()
    except CorazaError:
        return None
    try:
        return tx.interruption()
    except CorazaError:
        return None


def _finalize(tx: Any) -> None:
    try:
        tx.process_logging()
    except CorazaError:
        pass
    try:
        tx.close()
    except CorazaError:
        pass


__all__ = ["CorazaMiddleware"]
