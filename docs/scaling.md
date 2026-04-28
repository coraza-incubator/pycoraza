# Scaling pycoraza across workers

pycoraza embeds the OWASP Coraza WAF — a Go shared library — into your
Python process. Inside one process, a single `WAF` is thread-safe and
should be shared across all request workers (Go's runtime handles
scheduling). Across processes, **each worker must build its own
`WAF`**: Go's runtime state does not survive `fork()`, and the
runtime cannot be re-initialized inside an already-imported worker.

This document is the short, concrete recipe.

## TL;DR

- One `WAF` per worker process.
- Threads inside that worker share the `WAF` for free.
- `WAFRef` is a thin reference wrapper, not a multi-process pool.
- The pre-1.0 `WAFPool` name is a deprecated alias for `WAFRef`.

## gunicorn (Flask, Django, any WSGI app)

`gunicorn` has two ways to start workers: forked from a parent
process (default) and `--preload`. `--preload` imports your app **once
in the parent**, then forks workers. With pycoraza, that import
initializes the Go runtime in the parent — but the runtime cannot
survive the fork into the workers. **Do not use `--preload` with
pycoraza.**

Each worker should build the WAF on its own. The simplest pattern: do
it at import time inside the app module, so each forked worker
re-imports and re-initializes.

```python
# app.py
from flask import Flask
from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.coreruleset import recommended
from pycoraza.flask import CorazaMiddleware

waf = create_waf(WAFConfig(rules=recommended(), mode=ProcessMode.BLOCK))

app = Flask(__name__)
app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)
```

Run it with:

```sh
gunicorn -w 4 app:app
```

Each of the 4 workers gets its own `WAF` and its own Go runtime.

### Why not `--preload`?

`gunicorn --preload` imports your app in the master process before
forking. `pycoraza` (specifically the cgo binding to libcoraza) loads
the Go runtime as a side effect of the first `pycoraza` import. After
fork, Go's runtime — its goroutine schedulers, its sigaltstack, its
internal locks — is in a half-broken state in each child. You will
see hangs, signal-handler corruption, or crashes on the first
request. **Always omit `--preload`** when running pycoraza under
gunicorn.

## uvicorn (FastAPI, Starlette, any ASGI app)

`uvicorn --workers N` spawns workers via the `multiprocessing`
"spawn" method on Linux when `--workers > 1`. Each worker is a fresh
Python process, so each one initializes pycoraza independently.
Define the WAF at module scope:

```python
# main.py
from fastapi import FastAPI
from pycoraza import ProcessMode, WAFConfig, create_waf
from pycoraza.coreruleset import recommended
from pycoraza.starlette import CorazaMiddleware

waf = create_waf(WAFConfig(rules=recommended(), mode=ProcessMode.BLOCK))

app = FastAPI()
app.add_middleware(CorazaMiddleware, waf=waf)
```

```sh
uvicorn main:app --workers 4
```

For the single-worker case (`--workers 1`), uvicorn runs entirely in
the main process; the same WAF is shared across all asyncio
coroutines on the event loop. Heavy concurrency (100+ in-flight
requests) saturates the default thread pool — pass
`thread_limit=128` to `CorazaMiddleware` if you measure it.

## hypercorn

Same shape as uvicorn. Use `hypercorn --workers N main:app`.

## Worker count

Start with `2 × CPU cores`, measure, adjust. The WAF adds
single-digit-millisecond latency per request; the bottleneck is
usually downstream of the middleware, not in it.

## Things to avoid

1. **Sharing a `WAF` across processes via `multiprocessing.Manager`
   or pickling.** The handle wraps an opaque C pointer into a Go
   runtime that exists only in the process that created it. Pickling
   it is a foot-gun: it appears to work, then segfaults under load.
2. **Re-importing pycoraza inside a worker after a fork.** The Go
   runtime cannot be initialized twice in the same process and
   cannot survive a fork. If you must use a forking server, ensure
   pycoraza is imported only inside the worker (not in the parent).
3. **`importlib.reload(pycoraza)`.** Unsupported. The Go runtime
   does not support re-init.
4. **Custom signal handlers installed before importing pycoraza.**
   See `docs/threat-model.md` and `src/pycoraza/_signals.py` — Go
   installs `SIGSEGV`/`SIGBUS`/`SIGPROF`/`SIGURG` handlers on first
   import. Install your own handlers AFTER importing `pycoraza`, or
   call the helpers in `_signals.py` to recover after the import.

## Why is there no real multi-process pool?

A real pool would spawn N worker processes, each with its own WAF,
and dispatch transactions across them via IPC. That layer doesn't
belong in this library — every Python WSGI / ASGI server already has
a battle-tested multi-process worker model (gunicorn, uvicorn,
hypercorn, Granian). Stacking another one on top of those would only
multiply the failure modes. Use the server's worker model; build
one `WAF` per worker.
