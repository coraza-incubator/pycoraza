"""Django views that implement the shared HTTP contract."""

from __future__ import annotations

import json
from typing import Any

import pycoraza_shared as shared
from django.http import HttpRequest, HttpResponse, JsonResponse

ADAPTER_NAME = "django"


def _render(result: shared.HandlerResult) -> HttpResponse:
    body = result.body
    ctype = result.content_type
    if isinstance(body, (bytes, bytearray)):
        return HttpResponse(
            bytes(body),
            status=result.status,
            content_type=ctype or "application/octet-stream",
        )
    if isinstance(body, str):
        return HttpResponse(
            body, status=result.status, content_type=ctype or "text/plain; charset=utf-8"
        )
    return JsonResponse(body, status=result.status, safe=False)


def root(_request: HttpRequest) -> HttpResponse:
    return _render(shared.root(ADAPTER_NAME))


def healthz(_request: HttpRequest) -> HttpResponse:
    return _render(shared.healthz())


def search(request: HttpRequest) -> HttpResponse:
    return _render(shared.search(request.GET.get("q")))


def echo(request: HttpRequest) -> HttpResponse:
    raw = request.body or b""
    payload: Any
    if raw:
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw.decode("utf-8", errors="replace")
    else:
        payload = {}
    return _render(shared.echo(payload))


def upload(request: HttpRequest) -> HttpResponse:
    raw = request.body or b""
    return _render(shared.upload(len(raw)))


def image(_request: HttpRequest) -> HttpResponse:
    return _render(shared.image())


def user(_request: HttpRequest, user_id: str) -> HttpResponse:
    return _render(shared.user(user_id))


def ftw_catch_all(request: HttpRequest) -> HttpResponse:
    headers = {k.lower(): v for k, v in request.headers.items()}
    raw = request.body or b""
    url = request.path
    if request.META.get("QUERY_STRING"):
        url = f"{url}?{request.META['QUERY_STRING']}"
    result = shared.ftw_echo_handler(
        shared.FtwEchoInput(
            method=request.method or "GET",
            url=url,
            headers=headers,
            body=raw.decode("utf-8", errors="replace"),
        )
    )
    return _render(result)
