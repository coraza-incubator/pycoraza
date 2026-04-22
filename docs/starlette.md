# Starlette adapter

ASGI middleware that runs pycoraza in front of a Starlette app.

The same middleware class powers the FastAPI adapter (FastAPI re-exports
it). If you use FastAPI, the [`./fastapi.md`](./fastapi.md) page has
FastAPI-specific idioms; this page is the Starlette reference.

For a 5-minute tour, see [`./quickstart.md`](./quickstart.md).

## Install

```bash
pip install "pycoraza[fastapi]"   # same extra — pulls starlette
```

## Minimum working example

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.starlette import CorazaMiddleware

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

async def index(request):
    return JSONResponse({"ok": True})

app = Starlette(
    routes=[Route("/", index)],
    middleware=[Middleware(CorazaMiddleware, waf=waf)],
)
```

Starlette takes a list of `Middleware(cls, **kwargs)` entries on
construction. pycoraza goes at the outer edge so it sees raw request
bytes before any other middleware has touched them.

## Options

Identical to the FastAPI adapter — the class is the same.

```python
Middleware(
    CorazaMiddleware,
    waf=waf,
    on_block=None,              # async callable
    inspect_response=False,
    on_waf_error="block",       # "block" | "allow"
    skip=None,
)
```

### `waf`

A `WAF` from `create_waf(WAFConfig(...))`. Thread-safe and sharable.

### `on_block`

Async; same signature as the FastAPI adapter:

```python
async def on_block(interruption, scope, send) -> bool:
    # return True if you called send() yourself
    ...
```

Return `True` if your handler fully emitted the response. Return
`False` or fall off the end to get the default JSON 403.

Example: custom HTML block.

```python
async def on_block(intr, scope, send):
    body = b"<!doctype html><h1>blocked</h1>"
    await send({
        "type": "http.response.start",
        "status": 403,
        "headers": [
            (b"content-type", b"text/html; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
    return True

app = Starlette(
    routes=[...],
    middleware=[Middleware(CorazaMiddleware, waf=waf, on_block=on_block)],
)
```

### `inspect_response`

When `True`, wraps `send` to capture response headers and body and
run phase 3+4 rules. Response body is buffered until the final chunk
— streaming responses lose their streaming semantics under
inspection.

Enable when you have response-side rules. See
[`./crs-profiles.md`](./crs-profiles.md) for how to tune the outbound
rule categories.

### `on_waf_error`

- `"block"` (default) — 500 on transaction setup failure.
- `"allow"` — raises `CorazaError` rather than silently passing
  through. The request body has already been consumed by the
  middleware at that point, so passing through isn't safe without
  coordination. See [`./fastapi.md`](./fastapi.md#on_waf_error) for
  the rationale.

### `skip`

Same as Flask and FastAPI. `None`, `True`, `False`, `SkipOptions`, or
a predicate.

```python
from pycoraza import SkipOptions

Middleware(
    CorazaMiddleware, waf=waf,
    skip=SkipOptions(extra_paths=("/healthz",)),
)
```

## Production deployment

### Uvicorn workers

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

Each uvicorn worker is its own process with its own libcoraza. The
`WAF` instance is created at module-import time inside each worker.

### Hypercorn

Starlette also works under hypercorn:

```bash
hypercorn app:app --bind 0.0.0.0:8000 --workers 4
```

Same semantics as uvicorn — one libcoraza per worker process.

### Logging

Starlette uses the stdlib `logging` module. The pycoraza logger is
`pycoraza`:

```python
import logging
logging.getLogger("pycoraza").setLevel(logging.INFO)
```

For rule-match detail, pass a custom `Logger` into `WAFConfig`.
pycoraza's logger protocol is small; see `src/pycoraza/logger.py`.

### Middleware ordering

Put pycoraza first (outermost) in the middleware list. It needs to
see the raw request before any other middleware has transformed it.

```python
app = Starlette(
    middleware=[
        Middleware(CorazaMiddleware, waf=waf),
        Middleware(GZipMiddleware),
        Middleware(AuthMiddleware),
    ],
)
```

If you put pycoraza after something that decodes or rewrites the
body, Coraza will see the post-transform bytes, not what the attacker
sent.

### Health checks

Bypass liveness / readiness probes:

```python
Middleware(
    CorazaMiddleware, waf=waf,
    skip=SkipOptions(extra_paths=("/healthz", "/readyz")),
)
```

## Differences from the Flask adapter

The ASGI middleware class is not just a port of the Flask one; it's
async-shaped throughout.

- `on_block` is async and returns `bool` (did the handler emit the
  response).
- Body reading buffers the full body before handing control to the
  downstream app, then replays it through a wrapped `receive`.
- Coraza calls happen in a thread via `asyncio.to_thread` so the
  event loop isn't blocked.
- WAF-error `"allow"` mode raises rather than passing through,
  because `receive` has already been consumed.

## See also

- [`./fastapi.md`](./fastapi.md) — the same adapter, FastAPI idioms.
- [`./quickstart.md`](./quickstart.md) — 5-minute tutorial.
- [`./threat-model.md`](./threat-model.md) — fail-closed guarantees.
- [`./crs-profiles.md`](./crs-profiles.md) — rule-set tuning.
