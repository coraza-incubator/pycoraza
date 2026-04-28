# Middleware ordering

Where pycoraza belongs in your middleware stack — and what breaks if
you put it in the wrong slot.

This page exists because the most common deployment mistake is not "I
configured the WAF wrong" but "I put it AFTER gzip / auth / a body
parser, so it never sees what the attacker sent." pycoraza only blocks
attacks it sees. If a middleware ahead of it has already rewritten or
consumed the request, the WAF is inspecting the wrong bytes.

For the security-side rationale on fail-closed behavior, see
[`./threat-model.md`](./threat-model.md). This page is purely about
ordering.

## One-page rule of thumb

```
wire
  -> [reverse-proxy header normalize]   ProxyFix / TrustedHostMiddleware
  -> [pycoraza CorazaMiddleware]        WAF runs here
  -> [auth / csrf / sessions]
  -> [body parsers]                     Pydantic / DRF / WTForms
  -> handler
```

What sits ABOVE pycoraza:

- Reverse-proxy header normalization. The WAF needs the real client
  IP for `REMOTE_ADDR`, not your load balancer's. ProxyFix
  (Werkzeug), `TrustedHostMiddleware` (Starlette), and Django's
  `USE_X_FORWARDED_HOST` belong above.
- Static-asset serving (Whitenoise, `StaticFiles`) — optionally — if
  you want static requests to never enter the WAF code path. The
  alternative is to leave Coraza on top and rely on the default
  `skip` predicate to bypass `.css`/`.js`/etc. Both are valid; see
  [Static-asset coexistence](#static-asset-coexistence).

What sits BELOW pycoraza:

- Compression (gzip). If gzip runs before the WAF, Coraza sees
  compressed bytes and every `@rx` rule is meaningless.
- Authentication, CSRF, sessions. Otherwise an attacker can DoS
  your auth backend or session store with payloads the WAF would
  have blocked at the edge.
- Body parsers (Pydantic, DRF, WTForms). The body must be available
  to the WAF before the parser claims it; pycoraza buffers and
  re-delivers, so the parser still gets a fresh body — but only if
  it runs after pycoraza. See
  [Body-parser interaction](#body-parser-interaction).

## Per-framework recipes

### Flask

WSGI is a callable chain, not a list. The "outermost" wrapper runs
first. ProxyFix MUST wrap pycoraza, and pycoraza MUST wrap everything
else (Flask-Compress, Flask-Login, Flask-WTF/CSRF).

```python
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_compress import Compress
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.flask import CorazaMiddleware

app = Flask(__name__)

# Body parsers, CSRF, auth — these read request.form / request.json,
# which pulls from the WSGI body. They run inside Flask, BELOW the
# WSGI wrappers, so they automatically sit "after" pycoraza in
# request order.
CSRFProtect(app)
login_manager = LoginManager(app)
Compress(app)  # Flask-Compress operates on the response, after handlers

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

# Order: outermost wrapper runs first on the request path.
# ProxyFix -> pycoraza -> Flask app
app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

Because WSGI wraps from the inside out, the LAST `app.wsgi_app = ...`
assignment is the OUTERMOST wrapper — that's where ProxyFix goes.
pycoraza is wrapped one level in, so it sees the
ProxyFix-rewritten `REMOTE_ADDR`.

Flask-Compress is registered as a Flask extension (`Compress(app)`),
not as a WSGI wrapper. It hooks `after_request` and operates on the
response, which is fine: gzip-of-response runs AFTER pycoraza has
already inspected the request body.

### Django

Django's `MIDDLEWARE` list runs top-down on the request and bottom-up
on the response. **Put `pycoraza.django.CorazaMiddleware` near the
top so it runs FIRST on incoming requests.** A few of the SecurityMiddleware
checks (HOST header validation) run earlier than that — and that's
fine: those rejects happen before any body is read.

```python
# settings.py
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import python_web

PYCORAZA_WAF = create_waf(WAFConfig(
    rules=python_web(paranoia=1),
    mode=ProcessMode.BLOCK,
))

USE_X_FORWARDED_HOST = True  # honor X-Forwarded-Host from the LB
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

MIDDLEWARE = [
    # 1. Host validation (rejects bad Host before body is read).
    "django.middleware.security.SecurityMiddleware",

    # 2. WAF — first thing that touches the body.
    "pycoraza.django.CorazaMiddleware",

    # 3. Sessions, auth, CSRF — these can use the request body
    #    (csrfmiddlewaretoken in form data), so they MUST come
    #    after pycoraza. Django re-reads request.body via
    #    HttpRequest.body, which is cached after first read; the
    #    middleware's body buffering is compatible.
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    # 4. Compression — runs on the response side. Because Django
    #    middleware reverses on response, GZipMiddleware here will
    #    be the FIRST middleware to touch the response (compressing
    #    last), and pycoraza will see the response BEFORE it is
    #    compressed when inspect_response is enabled. That's the
    #    correct order for response-side rules.
    "django.middleware.gzip.GZipMiddleware",
]
```

**Subtle Django-only ordering note:** `MIDDLEWARE` is processed
top-down for `process_request` and bottom-up for `process_response`.
`GZipMiddleware` placed at the bottom means: first to compress on
response (it's the innermost wrap of the response). pycoraza, placed
near the top, sees the uncompressed response when `inspect_response=True`.
If you flip those two, pycoraza would inspect already-gzipped bytes
on the response side and every phase 4 rule becomes a no-op.

### FastAPI

FastAPI's `add_middleware()` builds a Starlette middleware stack.
Order matters: **the LAST `add_middleware` call is the OUTERMOST
wrapper** — it runs first on the request. So you add them in
reverse order of execution.

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.fastapi import CorazaMiddleware

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

api = FastAPI()

# Order of execution on a request: outer-first.
# We add INNERMOST first; the LAST add_middleware is OUTERMOST.

# Innermost: gzip (operates on response only).
api.add_middleware(GZipMiddleware, minimum_size=1000)
# Then CORS (response headers; benign for request body).
api.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])
# Then pycoraza (sees raw request).
api.add_middleware(CorazaMiddleware, waf=waf)
# Outermost: TrustedHost / X-Forwarded-* normalization.
# Runs FIRST on the request — pycoraza then sees the rewritten host.
api.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com"])
```

If you flip CORS above pycoraza, the WAF still works — CORS doesn't
modify the body. But if you flip `GZipMiddleware` above pycoraza,
**outbound** inspection (`inspect_response=True`) sees compressed
bytes and is useless. Phase 1+2 (request side) are unaffected
because gzip doesn't touch the request body.

### Starlette

Starlette uses an explicit `Middleware(cls, **kwargs)` list passed at
construction. The list is **outer-to-inner in declaration order** —
the first entry is the outermost wrapper.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Route

from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.starlette import CorazaMiddleware

waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

middleware = [
    # First entry runs FIRST on the request (outermost).
    Middleware(TrustedHostMiddleware, allowed_hosts=["example.com"]),
    Middleware(CorazaMiddleware, waf=waf),
    Middleware(CORSMiddleware, allow_origins=["https://example.com"]),
    Middleware(GZipMiddleware, minimum_size=1000),
]

app = Starlette(routes=[...], middleware=middleware)
```

Note the inversion compared to FastAPI's `add_middleware`: Starlette's
list is outer-first; FastAPI's `add_middleware` calls are inner-first.
Same execution order; different declaration syntax.

### Generic ASGI

If you're not using Starlette or FastAPI, you compose ASGI middlewares
by wrapping. `CorazaMiddleware` is itself an ASGI middleware — it
implements `__call__(scope, receive, send)`. Wrap inside out:

```python
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.starlette import CorazaMiddleware  # works for any ASGI app


async def application(scope, receive, send):
    """Your bare ASGI app."""
    if scope["type"] != "http":
        return
    body = b'{"ok": true}'
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": body})


waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.BLOCK,
))

# Innermost first; outer wrappers wrap them.
app = CorazaMiddleware(application, waf=waf)
# If you have a header-normalizing middleware, wrap pycoraza in it:
# app = my_proxy_fix_asgi(app)

# Run with: uvicorn module:app --host 0.0.0.0 --port 8000
```

The same rule applies: any middleware that decompresses or rewrites
the request body must wrap pycoraza (run before it on requests). Any
middleware that operates on the response only — gzip, CORS — should be
wrapped BY pycoraza (run after on requests, before on responses).

## Static-asset coexistence

Two valid layouts.

### Option A: pycoraza on top; default `skip` bypasses static

This is the default and the simplest. Requests for `.png`, `.css`,
`.js`, `/static/`, `/_next/static/`, `/assets/`, `/favicon.ico` are
short-circuited inside pycoraza without creating a transaction.

```python
# Flask
app.wsgi_app = CorazaMiddleware(app.wsgi_app, waf=waf)  # default skip is on
```

```python
# Django
MIDDLEWARE = [
    "pycoraza.django.CorazaMiddleware",          # default skip
    "whitenoise.middleware.WhiteNoiseMiddleware",  # serves /static/
    # ...
]
```

The static request enters pycoraza, hits the skip predicate, and falls
through to Whitenoise without paying for a Coraza transaction. This is
the recommended default — it keeps the WAF in front for everything
even slightly suspicious (e.g. `/static/../etc/passwd`).

### Option B: static-file middleware ABOVE pycoraza

If you want static assets to never even enter the pycoraza module
(e.g. you have measured that the skip predicate is hot enough to
matter, or you want zero WAF logging for static requests), put the
static handler first.

```python
# Django
MIDDLEWARE = [
    "whitenoise.middleware.WhiteNoiseMiddleware",  # serves and returns
    "pycoraza.django.CorazaMiddleware",            # only sees non-static
    # ...
]
```

```python
# FastAPI / Starlette — mount StaticFiles before adding pycoraza,
# so requests under /static/ are routed by StaticFiles directly.
from fastapi.staticfiles import StaticFiles
api.mount("/static", StaticFiles(directory="static"), name="static")
api.add_middleware(CorazaMiddleware, waf=waf)
# Requests to /static/... are routed by mount before middleware fires.
```

Tradeoff: a request for `/static/../../etc/passwd` is now Whitenoise's
problem. Whitenoise rejects path traversal in its router (it does;
audited), but you lose CRS-930 LFI rule coverage on that prefix. Pick
Option A unless you have a measured reason for Option B.

See [`./threat-model.md`](./threat-model.md) for the broader
fail-closed posture.

## Body-parser interaction

pycoraza's adapters all buffer the request body, hand it to libcoraza
for evaluation, and re-deliver it to the downstream app. The downstream
parser sees the original bytes and parses normally.

| Framework | How re-read works |
|---|---|
| Flask (WSGI) | `environ["wsgi.input"]` is replaced with an `io.BytesIO` over the buffered body. `request.form` / `request.json` reads it like any other stream. |
| Django (WSGI) | `request._stream` is reset; `HttpRequest.body` returns the buffered bytes. DRF's parsers use `request.body` and the cached property survives. |
| FastAPI / Starlette (ASGI) | The wrapped `receive` re-emits `http.request` messages with the buffered chunks. Pydantic body-binding receives them transparently. |
| Generic ASGI | Same as Starlette — `receive` is wrapped to replay the buffered body. |

This means **body parsers must run AFTER pycoraza in the middleware
order**. They will, by default — Pydantic body-binding and DRF parsers
are inside the handler, not in the middleware stack, so they're always
"below" middleware. The only way to break this is to insert a
custom middleware that calls `await request.body()` (Starlette) or
`request.body` (Django) before pycoraza runs; don't do that.

## Reverse-proxy chain

When pycoraza runs behind Cloudflare, AWS ALB, Nginx, or any other
reverse proxy, the TCP source IP at the wsgi/asgi layer is the proxy,
not the real client. CRS rules that reference `REMOTE_ADDR`
(IP-reputation lookups, GeoIP) need the real client IP.

The fix is the same on every framework: put a header-normalization
middleware ABOVE pycoraza so by the time pycoraza reads
`environ["REMOTE_ADDR"]` (WSGI) or `scope["client"]` (ASGI), the value
already reflects `X-Forwarded-For` or `True-Client-IP`.

- **Flask / Werkzeug**: `werkzeug.middleware.proxy_fix.ProxyFix(app, x_for=1, x_proto=1, x_host=1)`. Set `x_for` to the number of trusted proxies in the chain.
- **Django**: `USE_X_FORWARDED_HOST = True` plus a custom middleware that rewrites `REMOTE_ADDR` from `HTTP_X_FORWARDED_FOR`. Django does NOT do this for you out of the box — `SECURE_PROXY_SSL_HEADER` only handles scheme. Use `django-ipware` or write the four-line middleware yourself, and place it ABOVE `pycoraza.django.CorazaMiddleware`.
- **FastAPI / Starlette**: `TrustedHostMiddleware` validates `Host` but does NOT rewrite `client`. Use uvicorn's `--proxy-headers --forwarded-allow-ips '*'` flag to make uvicorn populate `scope["client"]` from `X-Forwarded-For` before any middleware runs.

> **Forward-looking:** A future `extract_client_ip` helper will let
> pycoraza pull the real client IP from a configured trusted-proxy
> chain regardless of upstream middleware. Until then, normalize
> ABOVE the WAF.

## Layered WAF posture

If you already run Cloudflare WAF, AWS WAF, or another edge WAF in
front of your origin, some CRS rule families are redundant. CRS-913
(scanner detection) is the most common: Cloudflare already blocks
known scanner UA strings before traffic reaches you.

Disable redundant categories at WAF construction:

```python
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended

waf = create_waf(WAFConfig(
    rules=recommended(
        paranoia=1,
        # Cloudflare already detects scanners at the edge —
        # don't pay for it twice.
        exclude_categories=("913",),
    ),
    mode=ProcessMode.BLOCK,
))
```

`exclude_categories` accepts the CRS prefix codes — `"913"` for
scanner detection, `"949"` for the inbound blocking-evaluation phase
(do NOT exclude this; it's how anomaly scoring decides to block),
`"955"` for web-shell detection on responses. See
[`./crs-profiles.md`](./crs-profiles.md) for the full category list.

The general rule: only exclude a category if the upstream WAF blocks
the same families AND you've verified the upstream WAF logs you can
see don't show holes you'd want pycoraza to backstop.

## Common mistakes

| Wrong ordering | What breaks | Fix |
|---|---|---|
| `GZipMiddleware` above pycoraza on the request side | pycoraza inspects already-compressed bytes; every `@rx` rule becomes a no-op. | Move pycoraza ABOVE gzip. (Flask: wrap pycoraza after Compress is registered. Django: put pycoraza first; gzip last. FastAPI: `add_middleware(GZipMiddleware)` BEFORE `add_middleware(CorazaMiddleware)`.) |
| `CsrfViewMiddleware` / Flask-WTF / `AuthenticationMiddleware` above pycoraza | Auth backend / CSRF check fires on attacker payloads, burning DB lookups and session-store cycles. Auth-store DoS is now an attack surface. | Place pycoraza ABOVE auth/CSRF/sessions. The WAF blocks 99% of attack payloads before auth is consulted. |
| No proxy-header normalization above pycoraza | `REMOTE_ADDR` is the load balancer; CRS IP-reputation rules and per-IP rate-limit-style rules see one client (the LB) for everyone. | Put ProxyFix (Flask) or `--proxy-headers` (uvicorn) ABOVE pycoraza, OR wait for `extract_client_ip` (forward-looking). |

## See also

- [`./flask.md`](./flask.md) — Flask adapter reference.
- [`./fastapi.md`](./fastapi.md) — FastAPI adapter reference.
- [`./starlette.md`](./starlette.md) — Starlette adapter reference.
- [`./threat-model.md`](./threat-model.md) — fail-closed defaults and
  why ordering is a security decision.
- [`./crs-profiles.md`](./crs-profiles.md) — `exclude_categories` and
  paranoia levels.
