# Flask adapter

WSGI middleware that runs pycoraza in front of a Flask app.

For a 5-minute tour, see [`./quickstart.md`](./quickstart.md). This
page covers every option, `on_block` customization, response
inspection, the static-asset bypass, and production deployment.

## Install

```bash
pip install "pycoraza[flask]"
```

The `[flask]` extra pulls Flask itself. The adapter module is
`pycoraza.flask` and its entry point is `CorazaMiddleware`.

## Minimum working example

```python
from flask import Flask
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.flask import CorazaMiddleware

app = Flask(__name__)

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)

@app.get("/")
def index():
    return {"ok": True}
```

The middleware wraps `app.wsgi_app` rather than using `app.before_request`
so it sees the raw WSGI environ — query strings, headers, and body
before Flask has parsed them.

## Options

```python
CorazaMiddleware(
    app,
    *,
    waf,                       # required: a WAF built with create_waf()
    on_block=None,             # optional: custom block handler
    inspect_response=False,    # enable phase 3+4 (response rules)
    on_waf_error="block",      # "block" | "allow" on adapter-level errors
    skip=None,                 # static-asset bypass predicate or options
)
```

### `waf`

A `WAF` instance from `create_waf(WAFConfig(...))`. The WAF is
thread-safe; share one across gunicorn workers and threads.

### `on_block`

A callable invoked when a rule blocks the request. Signature:

```python
def on_block(interruption, environ, start_response):
    ...
```

- `interruption` — an `Interruption` dataclass with `rule_id`,
  `action`, `status`, `data`, and optional `source`.
- `environ` — the WSGI environ dict.
- `start_response` — the WSGI `start_response` callable.

Return an iterable of bytes (the response body), or return `None` to
fall back to the default JSON block response.

Example: log the block and return HTML.

```python
import logging

log = logging.getLogger("pycoraza.block")

def on_block(intr, environ, start_response):
    log.warning(
        "coraza-block path=%s rule=%s data=%s",
        environ.get("PATH_INFO"), intr.rule_id, intr.data,
    )
    body = b"<!doctype html><h1>403 blocked</h1>"
    start_response(
        "403 Blocked",
        [("Content-Type", "text/html; charset=utf-8"),
         ("Content-Length", str(len(body)))],
    )
    return [body]

app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf, on_block=on_block)
```

The default handler returns a compact JSON body with the rule id,
action, and match data. See `_default_on_block` in
`src/pycoraza/flask/__init__.py`.

### `inspect_response`

When `True`, the middleware captures response headers and body and
evaluates CRS phase 3 (response headers) and phase 4 (response body)
rules. This doubles per-request overhead.

Enable when you have rules that depend on response content — CRS
outbound rules (categories 950–959) check for information
disclosure, stack traces, and path leakage. If you don't enable
response-side CRS rules (via `outbound_exclude`), there's nothing for
phase 3+4 to do, and you're paying for nothing.

**Cost:** response body is buffered in memory before emission. Avoid
enabling on endpoints that stream large payloads.

### `on_waf_error`

Controls what happens when libcoraza raises a `CorazaError` during
transaction setup or evaluation:

- `"block"` (default) — return 500 and drop the request. Fail-closed.
- `"allow"` — fall through to the downstream app. Fail-open.

Choose `"allow"` only when availability is strictly more important
than security for this deployment — e.g. a stateless health-check
endpoint behind another WAF layer. Default is `"block"` for a reason;
see [`./threat-model.md`](./threat-model.md#fail-closed-defaults).

### `skip`

Static-asset bypass. The adapter checks this first; paths that match
the predicate are passed to the downstream app without a transaction.

Accepted values:

- `None` / `True` — use built-in defaults (images, CSS, JS, fonts,
  `/static/`, `/_next/static/`, `/assets/`, `/favicon.ico`).
- `False` — never skip. Every request goes through the WAF.
- `SkipOptions(extensions=..., prefixes=..., extra_paths=...)` —
  override the defaults.
- A callable `(path: str) -> bool` — custom predicate. Return `True`
  to skip.

Example: add a health-check route to the bypass.

```python
from pycoraza import SkipOptions
from pycoraza.flask import CorazaMiddleware

app.wsgi_app = CorazaMiddleware(
    app.wsgi_app,
    waf=waf,
    skip=SkipOptions(extra_paths=("/healthz", "/metrics")),
)
```

Or use a predicate:

```python
def skip(path: str) -> bool:
    return path.startswith("/docs/") or path == "/healthz"

app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf, skip=skip)
```

Predicate-based skip is fastest; SkipOptions is the ergonomic choice
when you just need to add a few paths.

## Production deployment

### Gunicorn + threads

pycoraza's WAF is thread-safe. Gunicorn with sync or gthread workers
is the simplest production deployment.

```bash
gunicorn -w 4 --threads 2 -b 0.0.0.0:8000 app:app
```

Each worker process imports `app.py` once, creates one `WAF` shared
across its two threads. With four workers you have four libcoraza
instances — that's fine; Go's runtime handles per-process state.

### Gunicorn + gevent

gevent patches blocking I/O but does not patch Go's runtime. pycoraza
works with gevent, but:

- **Run `monkey.patch_all()` BEFORE `import pycoraza`.** gevent's
  monkey patching rewrites `signal.signal`; doing it after pycoraza
  has loaded displaces Go's signal handlers.
- Expect one libcoraza init per worker process.

```python
# gunicorn_conf.py
import gevent.monkey
gevent.monkey.patch_all()
```

```bash
gunicorn -w 4 -k gevent -c gunicorn_conf.py -b 0.0.0.0:8000 app:app
```

### Logging

pycoraza emits structured log lines via the `pycoraza` logger. Wire
it into your aggregator the way you wire any stdlib logger.

```python
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
    stream=sys.stdout,
)
```

For rule-match detail, pass a custom `Logger` into `WAFConfig`:

```python
from pycoraza import WAFConfig, create_waf

waf = create_waf(WAFConfig(
    rules=recommended(),
    mode=ProcessMode.BLOCK,
    logger=my_logger,  # see pycoraza.logger.Logger
))
```

### Health checks

Bypass the WAF on the health check or it will eventually flag some
automated scan as an attack and you'll page yourself.

```python
app.wsgi_app = CorazaMiddleware(
    app.wsgi_app, waf=waf,
    skip=SkipOptions(extra_paths=("/healthz",)),
)
```

## Middleware ordering

For where `CorazaMiddleware` belongs relative to ProxyFix,
Flask-Compress, Flask-Login, and Flask-WTF/CSRF, see
[`./middleware-ordering.md`](./middleware-ordering.md#flask).

## See also

- [`./quickstart.md`](./quickstart.md) — 5-minute first-request tutorial.
- [`./middleware-ordering.md`](./middleware-ordering.md) — where the WAF goes in the stack.
- [`./threat-model.md`](./threat-model.md) — fail-closed guarantees.
- [`./crs-profiles.md`](./crs-profiles.md) — how to tune the rule set.
- [`./performance.md`](./performance.md) — latency and throughput.
