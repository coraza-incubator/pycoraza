"""Django middleware for pycoraza.

Settings:
    PYCORAZA_WAF                # required: a WAF instance
    PYCORAZA_ON_BLOCK           # callable(intr, request) -> HttpResponse
    PYCORAZA_INSPECT_RESPONSE   # bool, default False
    PYCORAZA_ON_WAF_ERROR       # "block" (default) | "allow"
    PYCORAZA_SKIP               # SkipArg

Supports Django 4.2+ / 5.x. WSGI and ASGI (sync-compatible).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..abi import CorazaError
from ..skip import build_skip_predicate
from ..types import Interruption, OnWAFError, ProcessMode, RequestInfo
from ..waf import WAF

try:
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured, MiddlewareNotUsed
    from django.http import HttpRequest, HttpResponse, JsonResponse
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "pycoraza.django requires Django — install with `pip install pycoraza[django]`"
    ) from exc


OnBlock = Callable[[Interruption, HttpRequest], HttpResponse]


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
        waf = getattr(settings, "PYCORAZA_WAF", None)
        if waf is None:
            raise MiddlewareNotUsed(
                "pycoraza.django.CorazaMiddleware: settings.PYCORAZA_WAF is not set; "
                "set it to a WAF instance created via pycoraza.create_waf()."
            )
        if not isinstance(waf, WAF):
            raise ImproperlyConfigured(
                "settings.PYCORAZA_WAF must be a pycoraza.WAF instance; "
                f"got {type(waf).__name__}"
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

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if self._skip(request.method or "GET", request.path or ""):
            return self._get_response(request)

        try:
            tx = self._waf.new_transaction()
        except CorazaError:
            return self._handle_waf_error(request)

        try:
            body = _read_body(request)
            interrupted = tx.process_request_bundle(
                _request_info_from_django(request), body
            )
            if interrupted:
                intr = tx.interruption()
                if intr is not None and self._waf.mode is ProcessMode.BLOCK:
                    try:
                        return self._on_block(intr, request)
                    finally:
                        _finalize(tx)
        except CorazaError:
            _finalize(tx)
            return self._handle_waf_error(request)

        try:
            response = self._get_response(request)
        except BaseException:
            _finalize(tx)
            raise

        if self._inspect_response:
            _inspect_response(tx, response)

        _finalize(tx)
        return response

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


def _read_body(request: HttpRequest) -> bytes | None:
    """Read `request.body` once. Django caches it internally."""
    try:
        data = request.body
    except Exception:
        return None
    return data or None


def _request_info_from_django(request: HttpRequest) -> RequestInfo:
    # Django's wsgiref dev server (and any wsgiref-based server) synthesizes
    # CONTENT_TYPE='text/plain' on bodyless GETs because email.Message's
    # default content type is text/plain. Forwarding that to Coraza causes
    # CRS 920420 ("Request content type not allowed by policy") to fire on
    # every health probe at paranoia>=2. Strip CONTENT_TYPE / CONTENT_LENGTH
    # when there's no body — they are not meaningful per PEP 3333 unless a
    # body exists.
    raw_len = request.META.get("CONTENT_LENGTH") or ""
    try:
        has_body = int(raw_len) > 0
    except (TypeError, ValueError):
        has_body = False

    headers: list[tuple[str, str]] = []
    for key, value in request.META.items():
        if not isinstance(value, str):
            continue
        if key.startswith("HTTP_"):
            headers.append((key[5:].replace("_", "-").lower(), value))
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value and has_body:
            headers.append((key.replace("_", "-").lower(), value))

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


def _inspect_response(tx: Any, response: HttpResponse) -> None:
    status = int(getattr(response, "status_code", 200))
    try:
        headers = [(str(k), str(v)) for k, v in response.items()]
    except Exception:
        headers = []
    try:
        tx.add_response_headers(headers)
        tx.process_response_headers(status)
    except CorazaError:
        return

    body = getattr(response, "content", b"") or b""
    if not isinstance(body, (bytes, bytearray)):
        return
    if body:
        try:
            tx.append_response_body(bytes(body))
        except CorazaError:
            return
    try:
        tx.process_response_body()
    except CorazaError:
        return


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
