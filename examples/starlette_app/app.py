"""Starlette example: pycoraza ASGI middleware over the shared contract.

Run with uvicorn:

    uvicorn examples.starlette_app.app:app --port 5002

Or simply:

    python examples/starlette_app/app.py

Override the port with `PYCORAZA_PORT=xxxx`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_SHARED_DIR = Path(__file__).resolve().parent.parent / "shared"
if _SHARED_DIR.is_dir() and str(_SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(_SHARED_DIR))

import pycoraza_shared as shared
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.starlette import CorazaMiddleware

ADAPTER_NAME = "starlette"
FTW = shared.ftw_mode_enabled()
_MODE_ENV = os.environ.get("PYCORAZA_MODE", "").lower()
MODE = (
    ProcessMode.BLOCK if _MODE_ENV == "block"
    else ProcessMode.DETECT if _MODE_ENV == "detect"
    else ProcessMode.BLOCK if FTW
    else ProcessMode.DETECT
)
PORT = int(os.environ.get("PYCORAZA_PORT", "5002"))
WAF_ENABLED = os.environ.get("PYCORAZA_WAF", "on").lower() != "off"

waf = create_waf(WAFConfig(rules=shared.crs_profile(FTW), mode=MODE)) if WAF_ENABLED else None


def _render(result: shared.HandlerResult) -> Response:
    body = result.body
    ctype = result.content_type
    if isinstance(body, (bytes, bytearray)):
        return Response(
            content=bytes(body),
            status_code=result.status,
            media_type=ctype or "application/octet-stream",
        )
    if isinstance(body, str):
        return PlainTextResponse(
            content=body,
            status_code=result.status,
            media_type=ctype or "text/plain; charset=utf-8",
        )
    return JSONResponse(
        content=body,
        status_code=result.status,
        media_type=ctype or "application/json",
    )


async def _root(_request: Request) -> Response:
    return _render(shared.root(ADAPTER_NAME))


async def _healthz(_request: Request) -> Response:
    return _render(shared.healthz())


async def _search(request: Request) -> Response:
    return _render(shared.search(request.query_params.get("q")))


async def _echo(request: Request) -> Response:
    raw = await request.body()
    payload: Any
    if raw:
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw.decode("utf-8", errors="replace")
    else:
        payload = {}
    return _render(shared.echo(payload))


async def _upload(request: Request) -> Response:
    raw = await request.body()
    return _render(shared.upload(len(raw)))


async def _image(_request: Request) -> Response:
    return _render(shared.image())


async def _user(request: Request) -> Response:
    user_id = request.path_params.get("user_id", "")
    return _render(shared.user(user_id))


async def _ftw_catch_all(request: Request) -> Response:
    headers = {k.lower(): v for k, v in request.headers.items()}
    raw = await request.body()
    url = request.url.path
    if request.url.query:
        url = f"{url}?{request.url.query}"
    result = shared.ftw_echo_handler(
        shared.FtwEchoInput(
            method=request.method,
            url=url,
            headers=headers,
            body=raw.decode("utf-8", errors="replace"),
        )
    )
    return _render(result)


_ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

if FTW:
    _routes = [Route("/{rest:path}", _ftw_catch_all, methods=_ALL_METHODS)]
else:
    _routes = [
        Route("/", _root, methods=["GET"]),
        Route("/healthz", _healthz, methods=["GET"]),
        Route("/search", _search, methods=["GET"]),
        Route("/echo", _echo, methods=["POST"]),
        Route("/upload", _upload, methods=["POST"]),
        Route("/img/logo.png", _image, methods=["GET"]),
        Route("/api/users/{user_id}", _user, methods=["GET"]),
    ]

_middleware = (
    [Middleware(CorazaMiddleware, waf=waf, inspect_response=FTW)]
    if WAF_ENABLED and waf is not None
    else []
)

app = Starlette(routes=_routes, middleware=_middleware)


if __name__ == "__main__":
    import uvicorn

    print(
        f"starlette :{PORT} waf=on mode={MODE.value}"
        f"{' FTW=1 paranoia=2' if FTW else ''}",
        flush=True,
    )
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
