# Django — pycoraza middleware

`pycoraza.django.CorazaMiddleware` is a class-based Django middleware
that runs every request through a Coraza WAF. Supports Django 4.2+
(WSGI and ASGI deployments) and 5.x.

## Install

```sh
pip install "pycoraza[django]"
```

## Minimum configuration

```python
# settings.py
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import python_web

PYCORAZA_WAF = create_waf(WAFConfig(
    rules=python_web(paranoia=1),
    mode=ProcessMode.BLOCK,
))

MIDDLEWARE = [
    "pycoraza.django.CorazaMiddleware",   # FIRST — block before other middleware runs
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # ... your other middleware
]
```

Place `pycoraza.django.CorazaMiddleware` **first** so attacks are
blocked before auth, CSRF, sessions, and logging consume request
state.

## All settings

| Setting | Default | Meaning |
|---|---|---|
| `PYCORAZA_WAF` | *required* | `pycoraza.WAF` instance from `create_waf()`. |
| `PYCORAZA_ON_BLOCK` | default 403 JSON | `callable(intr, request) -> HttpResponse`. Runs when a rule fires in BLOCK mode. |
| `PYCORAZA_INSPECT_RESPONSE` | `False` | When True, run phase 3/4 on response headers + body. Doubles per-request cost; enable only when you have response-side rules. |
| `PYCORAZA_ON_WAF_ERROR` | `"block"` | `"block"` → 500 on WAF errors (fail-closed). `"allow"` → pass through (fail-open). |
| `PYCORAZA_SKIP` | static-asset bypass | `SkipArg` — `SkipOptions`, callable `(method, path) -> bool`, or `False` to scan every request. |

If `PYCORAZA_WAF` is unset, the middleware raises
`django.core.exceptions.MiddlewareNotUsed` at startup. If it's set to
something other than a `WAF` instance, it raises `ImproperlyConfigured`.

## Custom block handler

```python
from django.http import JsonResponse, HttpResponseRedirect

def on_block(interruption, request):
    # Redirect UI clients, respond with JSON for API clients.
    if request.headers.get("Accept", "").startswith("application/json"):
        return JsonResponse(
            {"error": "forbidden", "rule_id": interruption.rule_id},
            status=interruption.status or 403,
        )
    return HttpResponseRedirect("/blocked.html")

PYCORAZA_ON_BLOCK = on_block
```

## Probe-path preset (opt-in)

Health checks and Prometheus endpoints burn WAF cycles for no security
benefit. Skip them explicitly — pycoraza defaults to NOT skipping
because `/metrics` can accept writes on pushgateway-style deployments.

```python
from pycoraza import SkipOptions, PROBE_PATHS, PROBE_METHODS

PYCORAZA_SKIP = SkipOptions(
    prefixes=SkipOptions.default_prefixes(),
    extra_paths=PROBE_PATHS,   # /healthz /health /metrics /readiness /livez /ping
    methods=PROBE_METHODS,     # HEAD OPTIONS
)
```

Only enable when your probe routes return static `200 OK` and carry
no application logic.

## Production

### gunicorn (WSGI)

```sh
gunicorn --workers 4 --worker-class sync \
    --access-logfile - --error-logfile - \
    django_app.wsgi:application
```

Sync workers keep the transaction model simple. `--workers` scales
linearly with CPU; libcoraza releases the GIL so multi-worker scaling
is clean.

### uvicorn (ASGI)

Django 4.2+ supports async views via ASGI:

```sh
uvicorn django_app.asgi:application \
    --workers 4 --host 0.0.0.0 --port 8000
```

The middleware's `__call__` runs synchronously. Django's request/response
flow on ASGI wraps it via `asgiref.sync` automatically. For full async
handling (avoiding the sync-to-async bridge on every request), enable
`async_capable = True` in a subclass and implement an async variant —
not shipped by default because the sync path is simpler to audit and
the WAF call dominates the latency anyway.

### Worker concurrency note

A single `WAF` instance is thread-safe (Go runtime handles the
scheduling). One WAF per worker process is correct; don't attempt to
share a WAF handle across `fork()` — Go's runtime state doesn't survive
the fork. Create the WAF in `settings.py` (module-scope) and gunicorn's
pre-fork model takes care of per-worker isolation.

## Running the example

```sh
cd examples/django_app
PYCORAZA_PORT=5003 python manage.py runserver 127.0.0.1:5003
# or
PYCORAZA_PORT=5003 gunicorn \
    --workers 4 --worker-class sync \
    -b 127.0.0.1:5003 \
    --chdir examples/django_app \
    django_app.wsgi:application
```

See [`examples/django_app/`](../examples/django_app/) for a runnable
project implementing the canonical test-contract (same 7 routes as
the Flask / FastAPI / Starlette examples).
