"""FastAPI example: pycoraza ASGI middleware over the shared contract.

Run with uvicorn:

    uvicorn examples.fastapi_app.app:app --port 5001

Or simply:

    python examples/fastapi_app/app.py

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

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.fastapi import CorazaMiddleware

import pycoraza_shared as shared

ADAPTER_NAME = "fastapi"
FTW = shared.ftw_mode_enabled()
_MODE_ENV = os.environ.get("PYCORAZA_MODE", "").lower()
MODE = (
    ProcessMode.BLOCK if _MODE_ENV == "block"
    else ProcessMode.DETECT if _MODE_ENV == "detect"
    else ProcessMode.BLOCK if FTW
    else ProcessMode.DETECT
)
PORT = int(os.environ.get("PYCORAZA_PORT", "5001"))
WAF_ENABLED = os.environ.get("PYCORAZA_WAF", "on").lower() != "off"

waf = create_waf(WAFConfig(rules=shared.crs_profile(FTW), mode=MODE)) if WAF_ENABLED else None

app = FastAPI(title="pycoraza-fastapi-example", docs_url=None, redoc_url=None)
if WAF_ENABLED and waf is not None:
    app.add_middleware(CorazaMiddleware, waf=waf, inspect_response=FTW)


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


if FTW:
    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def _ftw_catch_all(request: Request, full_path: str) -> Response:
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
else:
    @app.get("/")
    async def _root() -> Response:
        return _render(shared.root(ADAPTER_NAME))

    @app.get("/healthz")
    async def _healthz() -> Response:
        return _render(shared.healthz())

    @app.get("/search")
    async def _search(q: str | None = None) -> Response:
        return _render(shared.search(q))

    @app.post("/echo")
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

    @app.post("/upload")
    async def _upload(request: Request) -> Response:
        raw = await request.body()
        return _render(shared.upload(len(raw)))

    @app.get("/img/logo.png")
    async def _image() -> Response:
        return _render(shared.image())

    @app.get("/api/users/{user_id}")
    async def _user(user_id: str) -> Response:
        return _render(shared.user(user_id))


if __name__ == "__main__":
    import uvicorn

    print(
        f"fastapi :{PORT} waf=on mode={MODE.value}"
        f"{' FTW=1 paranoia=2' if FTW else ''}",
        flush=True,
    )
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
