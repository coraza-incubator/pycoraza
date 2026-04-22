# Quickstart

A newcomer-friendly path to your first blocked request in five minutes.

This page uses Flask because it has the smallest boilerplate. The same
pattern applies to FastAPI and Starlette — after you finish here, hop
over to [`./flask.md`](./flask.md), [`./fastapi.md`](./fastapi.md), or
[`./starlette.md`](./starlette.md) for the framework-specific notes.

## 1. Install

```bash
pip install "pycoraza[flask]"
```

Linux wheels ship `libcoraza.so` vendored — no system install
required. The `[flask]` extra pulls Flask itself; pick `[fastapi]` or
`[all]` if you need another adapter.

If you're installing from a source distribution, you need Go 1.25+
and SWIG 4+ on `PATH` to build libcoraza. Prefer the wheel.

## 2. Minimal Flask app

Save as `app.py`:

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

Three moving parts:

- `recommended(paranoia=1)` emits a SecLang rules string backed by
  the bundled CRS corpus. See [`./crs-profiles.md`](./crs-profiles.md)
  for alternatives (`balanced`, `strict`, `permissive`).
- `create_waf(WAFConfig(...))` constructs the WAF engine once, at
  import time. Reuse it across requests.
- `CorazaMiddleware` wraps the WSGI app and enforces rules in front
  of `index`.

Note: `mode=ProcessMode.BLOCK` is set explicitly. The library default
is `DETECT` (log-only). We are flipping to `BLOCK` for the purposes of
this quickstart — in production, do a detect-mode rollout first.

## 3. Run the app

```bash
python -m flask --app app run
```

Flask starts on `http://127.0.0.1:5000/`.

## 4. Trigger a block

In another shell:

```bash
curl -i "http://127.0.0.1:5000/?q=../../etc/passwd"
```

Expected output:

```http
HTTP/1.1 403 Blocked
Content-Type: application/json
Content-Length: ...

{"error":"blocked","rule_id":930110,"action":"deny","data":"path traversal attack"}
```

The request was intercepted by the CRS path-traversal rule (`930110`)
and never reached your Flask view function.

A normal request still works:

```bash
curl -i "http://127.0.0.1:5000/"
# → HTTP/1.1 200 OK
# → {"ok": true}
```

## 5. Switch to detect mode

Before you ship, try detect mode. Change `ProcessMode.BLOCK` to
`ProcessMode.DETECT`:

```python
waf = create_waf(WAFConfig(
    rules=recommended(paranoia=1),
    mode=ProcessMode.DETECT,
))
```

Rerun the malicious request. Now the app returns 200, but the WAF
still logs the match. This is the recommended starting point in
production — deploy in `DETECT` for a week, review false positives in
your log aggregator, then flip to `BLOCK`.

## 6. Learn more

- Framework-specific options, `on_block` handlers, production
  deployment — [`./flask.md`](./flask.md),
  [`./fastapi.md`](./fastapi.md), [`./starlette.md`](./starlette.md).
- CRS profile tuning — [`./crs-profiles.md`](./crs-profiles.md).
- Threat model, fail-closed defaults, Go-runtime caveats —
  [`./threat-model.md`](./threat-model.md).
- Performance numbers and benchmark methodology —
  [`./performance.md`](./performance.md).
