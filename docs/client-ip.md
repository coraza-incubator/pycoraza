# Real-client-IP extraction

Behind a reverse proxy, the wire-level remote address is the proxy's
IP. CRS rules that depend on the originating client (REQUEST-913
scanner detection, IP allowlists, anomaly scoring) silently no-op
without proper extraction.

Pass `extract_client_ip=` into `CorazaMiddleware` to fix that. The
default is unchanged — `REMOTE_ADDR` (Flask) / `scope['client'][0]`
(Starlette/FastAPI) — so existing deployments keep their current
behavior.

Three input shapes:

```python
extract_client_ip=None                 # default: server-supplied
extract_client_ip="cloudflare"         # built-in preset name
extract_client_ip=trusted_proxy(...)   # custom callable
```

Built-in presets: `"cloudflare"`, `"xff_first"`, `"xff_last"`. All
fall back to `REMOTE_ADDR` when their header is missing or malformed.

## Cloudflare

Cloudflare sets `CF-Connecting-IP` at its edge. The header is
spoofable unless the origin is configured to accept connections only
from Cloudflare's IP ranges; lock the origin down with their
[ip-list](https://www.cloudflare.com/ips/) in your firewall.

```python
from pycoraza.flask import CorazaMiddleware

app.wsgi_app = CorazaMiddleware(
    app.wsgi_app, waf=waf, extract_client_ip="cloudflare",
)
```

## AWS ALB

ALB **appends** the connecting client to `X-Forwarded-For`. The
rightmost entry is what the ALB observed on the wire.

```python
from pycoraza.starlette import CorazaMiddleware

app.add_middleware(CorazaMiddleware, waf=waf, extract_client_ip="xff_last")
```

## Nginx (single trusted proxy)

If Nginx prepends a single hop (`proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;`), the leftmost entry is the client.

```python
from pycoraza.flask import CorazaMiddleware

app.wsgi_app = CorazaMiddleware(
    app.wsgi_app, waf=waf, extract_client_ip="xff_first",
)
```

## gunicorn behind a proxy (general case)

Use `trusted_proxy()` when there are one or more trusted hops in front
of gunicorn. It walks the XFF chain right-to-left and returns the
first untrusted IP — the originating client.

```python
from pycoraza import trusted_proxy
from pycoraza.starlette import CorazaMiddleware

extract = trusted_proxy(trusted_cidrs=("10.0.0.0/8", "172.16.0.0/12"))
app.add_middleware(CorazaMiddleware, waf=waf, extract_client_ip=extract)
```

The default `trusted_cidrs` covers RFC1918, loopback, and `fd00::/8`.
Override it for your cloud LB ranges or VPC subnet.

## Custom callable

Anything that takes the framework request/scope and returns a string
works:

```python
def from_real_ip(environ_or_scope):
    if "REQUEST_METHOD" in environ_or_scope:
        return environ_or_scope.get("HTTP_X_REAL_IP", "")
    for k, v in environ_or_scope.get("headers", []):
        if k == b"x-real-ip":
            return v.decode("latin-1")
    return ""

app.wsgi_app = CorazaMiddleware(
    app.wsgi_app, waf=waf, extract_client_ip=from_real_ip,
)
```

If your extractor raises or returns an empty string, the adapter
falls back to the wire-level address — fail-safe, never empty.
