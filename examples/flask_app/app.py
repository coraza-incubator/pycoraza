"""Flask example: pycoraza WSGI middleware over the shared contract.

Run directly:

    python examples/flask_app/app.py

Or point any WSGI server at `app`. Override the port with
`PYCORAZA_PORT=xxxx`.

When `FTW=1`, the app mounts a single `/*` echo route, flips to
paranoia=2 / block-mode — matches the go-ftw baseline.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# Make the shared contract importable when running `python app.py`
# without installing `examples/shared`. Matches what the README says.
_SHARED_DIR = Path(__file__).resolve().parent.parent / "shared"
if _SHARED_DIR.is_dir() and str(_SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(_SHARED_DIR))

import pycoraza_shared as shared
from flask import Flask, Response, abort, request

from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.flask import CorazaMiddleware

ADAPTER_NAME = "flask"
FTW = shared.ftw_mode_enabled()
_MODE_ENV = os.environ.get("PYCORAZA_MODE", "").lower()
MODE = (
    ProcessMode.BLOCK if _MODE_ENV == "block"
    else ProcessMode.DETECT if _MODE_ENV == "detect"
    else ProcessMode.BLOCK if FTW
    else ProcessMode.DETECT
)
PORT = int(os.environ.get("PYCORAZA_PORT", "5000"))
WAF_ENABLED = os.environ.get("PYCORAZA_WAF", "on").lower() != "off"

waf = create_waf(WAFConfig(rules=shared.crs_profile(FTW), mode=MODE)) if WAF_ENABLED else None

app = Flask(__name__)


def _render(result: shared.HandlerResult) -> Response:
    """Render a shared `HandlerResult` as a Flask response."""
    body = result.body
    ctype = result.content_type
    if isinstance(body, (bytes, bytearray)):
        return Response(bytes(body), status=result.status, content_type=ctype or "application/octet-stream")
    if isinstance(body, str):
        return Response(body, status=result.status, content_type=ctype or "text/plain; charset=utf-8")
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    return Response(payload, status=result.status, content_type=ctype or "application/json")


if FTW:
    @app.route(
        "/",
        defaults={"_rest": ""},
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    @app.route(
        "/<path:_rest>",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    def _ftw_catch_all(_rest: str) -> Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        raw = request.get_data(cache=False) or b""
        body = raw.decode("utf-8", errors="replace")
        result = shared.ftw_echo_handler(
            shared.FtwEchoInput(
                method=request.method,
                url=request.full_path.rstrip("?") if request.query_string else request.path,
                headers=headers,
                body=body,
            )
        )
        return _render(result)
else:
    @app.get("/")
    def _root() -> Response:
        return _render(shared.root(ADAPTER_NAME))

    @app.get("/healthz")
    def _healthz() -> Response:
        return _render(shared.healthz())

    @app.get("/search")
    def _search() -> Response:
        return _render(shared.search(request.args.get("q")))

    @app.post("/echo")
    def _echo() -> Response:
        payload: Any = request.get_json(silent=True)
        if payload is None:
            raw = request.get_data(cache=False) or b""
            payload = raw.decode("utf-8", errors="replace") if raw else {}
        return _render(shared.echo(payload))

    @app.post("/upload")
    def _upload() -> Response:
        raw = request.get_data(cache=False) or b""
        return _render(shared.upload(len(raw)))

    @app.get("/img/logo.png")
    def _image() -> Response:
        return _render(shared.image())

    @app.get("/api/users/<user_id>")
    def _user(user_id: str) -> Response:
        if not user_id:
            abort(404)
        return _render(shared.user(user_id))


if WAF_ENABLED and waf is not None:
    app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)


if __name__ == "__main__":
    print(
        f"flask :{PORT} waf={'on' if WAF_ENABLED else 'off'} mode={MODE.value}"
        f"{' FTW=1 paranoia=2' if FTW else ''}",
        flush=True,
    )
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
