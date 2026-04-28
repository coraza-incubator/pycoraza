# FastAPI adapter

ASGI middleware that runs pycoraza in front of a FastAPI app.

FastAPI is built on Starlette. `pycoraza.fastapi.CorazaMiddleware`
is a thin re-export of `pycoraza.starlette.CorazaMiddleware` — same
class, same options. The two docs exist because users searching for
"pycoraza fastapi" should find a FastAPI-shaped page. For the deeper
ASGI reference, see [`./starlette.md`](./starlette.md).

For a 5-minute tour, see [`./quickstart.md`](./quickstart.md).

## Install

```bash
pip install "pycoraza[fastapi]"
```

The `[fastapi]` extra pulls Starlette (a FastAPI dependency anyway).
FastAPI itself is not listed — install it separately, or use
`pycoraza[all]`.

## Minimum working example

```python
from fastapi import FastAPI
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.fastapi import CorazaMiddleware

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

api = FastAPI()
api.add_middleware(CorazaMiddleware, waf=waf)

@api.get("/")
async def index():
    return {"ok": True}
```

`add_middleware` instantiates the middleware lazily; the `waf=`
keyword is forwarded to `CorazaMiddleware.__init__`.

## Options

```python
api.add_middleware(
    CorazaMiddleware,
    waf=waf,
    on_block=None,              # async callable; see below
    inspect_response=False,     # enable phase 3+4 response rules
    on_waf_error="block",       # "block" | "allow"
    skip=None,                  # static-asset bypass
)
```

### `waf`

A `WAF` from `create_waf(WAFConfig(...))`. Shared across all ASGI
workers in a single process.

### `on_block`

**Async** signature — differs from the Flask adapter:

```python
async def on_block(interruption, scope, send) -> bool:
    ...
```

- `interruption` — an `Interruption` dataclass.
- `scope` — the ASGI scope dict (method, path, headers, client).
- `send` — the ASGI `send` callable.

Return `True` if your handler fully handled the response (called
`send` for `http.response.start` and `http.response.body`). Return
`False` (or nothing) to let pycoraza emit the default JSON block
response.

Example: emit a custom HTML 403.

```python
async def on_block(intr, scope, send):
    body = b"<!doctype html><h1>403 blocked</h1>"
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

api.add_middleware(CorazaMiddleware, waf=waf, on_block=on_block)
```

### `inspect_response`

When `True`, the middleware wraps the downstream app's `send`
callable to capture response headers and body, then runs CRS phase
3+4. Rules that match block the response.

**Cost:** response body is buffered until the final chunk. Streaming
responses (SSE, chunked JSON) lose their streaming semantics when
inspection is on. Enable only when you have response-side rules and
your endpoints are not streaming.

### `on_waf_error`

- `"block"` (default) — return a 500 if `new_transaction` fails.
  Fail-closed.
- `"allow"` — re-raise. Note that under ASGI, the middleware has
  already consumed the `receive` channel by the time we find out the
  WAF is broken; pycoraza raises in `"allow"` mode rather than
  sending a half-drained request downstream. This is deliberate.

Choose `"allow"` only when you can also arrange for your ASGI stack
to gracefully recover from the raised `CorazaError`.

### `skip`

Identical to the Flask adapter. Accepts `None`, `True`, `False`,
a `SkipOptions`, or a predicate `(path: str) -> bool`.

```python
from pycoraza import SkipOptions

api.add_middleware(
    CorazaMiddleware, waf=waf,
    skip=SkipOptions(extra_paths=("/healthz", "/metrics")),
)
```

## Production deployment

### Uvicorn workers

Run FastAPI under uvicorn with multiple workers for throughput:

```bash
uvicorn app:api --host 0.0.0.0 --port 8000 --workers 4
```

Each worker is its own process — one libcoraza init per worker. The
WAF is created lazily on first request within each worker when using
`add_middleware` (FastAPI instantiates middlewares during app
startup).

### Gunicorn + UvicornWorker

For unified process management:

```bash
gunicorn app:api -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:8000
```

Same caveats: one libcoraza per worker, WAF created in each worker.

### asyncio.to_thread semantics

Coraza is synchronous. The ASGI adapter wraps every libcoraza call
in `asyncio.to_thread` so the event loop isn't blocked. This means a
slow rule evaluation will run on the default thread-pool executor
(by default sized at `min(32, os.cpu_count() + 4)`).

If rule evaluation latency bothers you, you can raise the thread
pool size via a startup hook:

```python
import asyncio

@api.on_event("startup")
async def _tune():
    loop = asyncio.get_running_loop()
    from concurrent.futures import ThreadPoolExecutor
    loop.set_default_executor(ThreadPoolExecutor(max_workers=64))
```

This is rarely needed. Most workloads are well-served by the default.

### Logging

FastAPI / uvicorn use the stdlib `logging` module. Plug pycoraza in
the same way:

```python
import logging

logging.basicConfig(level=logging.INFO)
pycoraza_log = logging.getLogger("pycoraza")
pycoraza_log.setLevel(logging.INFO)
```

For rule-match detail, pass a custom `Logger` into `WAFConfig`.

### Health checks

Bypass the WAF on your liveness and readiness probes:

```python
api.add_middleware(
    CorazaMiddleware, waf=waf,
    skip=SkipOptions(extra_paths=("/healthz", "/readyz")),
)
```

## Differences from the Flask adapter

- `on_block` is async and returns `bool` (did-handle) instead of a
  bytes iterable.
- Body handling is buffered-then-replayed rather than WSGI's stream
  read. The adapter re-delivers the buffered body on the first
  `receive()` call from the downstream app.
- Coraza calls happen in a thread via `asyncio.to_thread`.
- WAF-error path in `"allow"` mode raises rather than passing the
  request through, because `receive` has already been consumed.

## Middleware ordering

For where `CorazaMiddleware` belongs relative to `CORSMiddleware`,
`GZipMiddleware`, and `TrustedHostMiddleware`, see
[`./middleware-ordering.md`](./middleware-ordering.md#fastapi).

## See also

- [`./starlette.md`](./starlette.md) — same adapter, native Starlette
  usage.
- [`./quickstart.md`](./quickstart.md) — 5-minute first-request
  tutorial.
- [`./middleware-ordering.md`](./middleware-ordering.md) — where the
  WAF goes in the stack.
- [`./threat-model.md`](./threat-model.md) — fail-closed guarantees.
- [`./crs-profiles.md`](./crs-profiles.md) — rule-set tuning.
