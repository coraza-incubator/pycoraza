"""Shared HTTP contract implemented by every pycoraza example app.

Mirrors `coraza-node/examples/shared/src/index.ts` — the goal is
apples-to-apples behavior across Flask, FastAPI, and Starlette so a
single traffic generator or go-ftw corpus drives all three the same
way.

Route matrix:

  GET  /                → JSON {"ok": True, "name": "<adapter>"}
  GET  /healthz         → text "ok"
  GET  /search?q=...    → JSON {"q": q, "len": len(q)}
  POST /echo            → echo JSON body back
  POST /upload          → JSON {"bytes": len(body)}
  GET  /img/logo.png    → 1x1 transparent PNG (content-type image/png)
  GET  /api/users/:id   → JSON {"id": id}

When the app is started with `FTW=1`, a single catch-all route is
mounted that echoes method + URL + headers + body back. go-ftw fires
every CRS test case at it.

Framework-agnostic on purpose: handlers return plain dict/bytes/str
and each adapter translates to its own response type.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pycoraza.coreruleset import recommended

# 1x1 transparent PNG — enough to satisfy clients expecting image
# bytes and to exercise the adapter's static-asset skip path.
SAMPLE_PNG: bytes = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
])


@dataclass(slots=True, frozen=True)
class HandlerResult:
    """What the shared handlers return before the adapter renders it."""

    body: Any
    status: int = 200
    content_type: str | None = None


@dataclass(slots=True, frozen=True)
class RouteSpec:
    """One canonical route. `handler` is a zero/one-arg callable that
    returns a `HandlerResult`. See `routes()` for details."""

    method: str
    path: str
    name: str


def root(adapter: str) -> HandlerResult:
    return HandlerResult(body={"ok": True, "name": adapter})


def healthz() -> HandlerResult:
    return HandlerResult(body="ok", content_type="text/plain")


def search(q: str | None) -> HandlerResult:
    value = q or ""
    return HandlerResult(body={"q": value, "len": len(value)})


def echo(payload: Any) -> HandlerResult:
    return HandlerResult(body=payload if payload is not None else {})


def upload(size: int) -> HandlerResult:
    return HandlerResult(body={"bytes": size})


def image() -> HandlerResult:
    return HandlerResult(body=SAMPLE_PNG, content_type="image/png")


def user(user_id: str) -> HandlerResult:
    return HandlerResult(body={"id": user_id})


def routes() -> list[RouteSpec]:
    """List of canonical routes. Adapters iterate this for wiring."""
    return [
        RouteSpec("GET", "/", "root"),
        RouteSpec("GET", "/healthz", "healthz"),
        RouteSpec("GET", "/search", "search"),
        RouteSpec("POST", "/echo", "echo"),
        RouteSpec("POST", "/upload", "upload"),
        RouteSpec("GET", "/img/logo.png", "image"),
        RouteSpec("GET", "/api/users/{id}", "user"),
    ]


def ftw_mode_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Return True when `FTW=1` is set. go-ftw CI flips this for every
    adapter leg — the variable name is stable on purpose."""
    src = env if env is not None else os.environ
    return src.get("FTW") == "1"


@dataclass(slots=True, frozen=True)
class FtwEchoInput:
    method: str
    url: str
    headers: dict[str, str]
    body: str


def ftw_echo_handler(request_like: FtwEchoInput) -> HandlerResult:
    """Canonical FTW echo body. Every adapter emits byte-identical JSON
    so one overrides YAML applies to the whole matrix."""
    return HandlerResult(
        body={
            "method": request_like.method,
            "url": request_like.url,
            "headers": request_like.headers,
            "body": request_like.body,
        },
        content_type="application/json",
    )


def crs_profile(ftw: bool) -> str:
    """Return the SecLang rules string.

    FTW mode: paranoia=2 with anomaly-block (stricter, block-mode). The
    go-ftw corpus is tuned for this baseline.

    Normal demo mode: paranoia=1, default thresholds — light enough
    that the example apps don't flag benign traffic.
    """
    if ftw:
        return recommended(paranoia=2)
    return recommended()


__all__ = [
    "FtwEchoInput",
    "HandlerResult",
    "RouteSpec",
    "SAMPLE_PNG",
    "crs_profile",
    "echo",
    "ftw_echo_handler",
    "ftw_mode_enabled",
    "healthz",
    "image",
    "root",
    "routes",
    "search",
    "upload",
    "user",
]
