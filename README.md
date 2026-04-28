# pycoraza

OWASP Coraza Web Application Firewall for Python. Flask, FastAPI, and
Starlette middleware powered by [libcoraza](https://github.com/corazawaf/libcoraza)
— the C shared library wrapping the Go-based
[Coraza engine](https://github.com/corazawaf/coraza).

pycoraza is the Python sibling of
[coraza-node](https://github.com/jptosso/coraza-node). Same engine, same CRS
profile helpers, same security-first defaults (`mode=detect`, fail-closed on
WAF error, opt-in response inspection).

## Install

```sh
pip install pycoraza                 # core only
pip install "pycoraza[flask]"        # + Flask middleware
pip install "pycoraza[fastapi]"      # + FastAPI / Starlette middleware
pip install "pycoraza[django]"       # + Django middleware
pip install "pycoraza[all]"          # everything
```

Linux wheels ship `libcoraza.so` vendored — no system install required.
Source distribution requires Go 1.25+ and SWIG 4+ to build libcoraza from
source.

## Quick start — Flask

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

## Quick start — FastAPI

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

## Quick start — Starlette

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from pycoraza import create_waf, WAFConfig, ProcessMode
from pycoraza.coreruleset import recommended
from pycoraza.starlette import CorazaMiddleware

waf = create_waf(WAFConfig(rules=recommended(), mode=ProcessMode.BLOCK))

app = Starlette(middleware=[Middleware(CorazaMiddleware, waf=waf)])
```

## Defaults

- `mode=ProcessMode.DETECT` — logs, does not block. Flip to
  `ProcessMode.BLOCK` once you've reviewed false positives.
- `on_waf_error="block"` — fail-closed. If the WAF can't evaluate a
  request, the request is dropped. Opt into `"allow"` only for
  availability-critical deployments.
- `inspect_response=False` — response-side rules off by default. Enable
  only when you have rules that need the response body.
- Static-asset bypass is on by default — images, CSS, JS, fonts, and
  common static prefixes skip the WAF. Override via the `skip=` option.

## Performance

Per-route RPS, p50/p95/p99 latency, and overhead-vs-baseline numbers are
tracked under [`bench/`](./bench) and rendered into
[`docs/performance.md`](./docs/performance.md). The weekly
[`bench.yml`](./.github/workflows/bench.yml) workflow gates regressions.

## Security

- [Threat model](./docs/threat-model.md) — encoding edge cases, signal
  handling with the Go runtime, fail-closed guarantees.
- [Security policy](./SECURITY.md) — disclosure.
- Non-WAF code paths never swallow Coraza errors silently.

## Development

```sh
git submodule update --init             # pull libcoraza
./native/scripts/build-libcoraza.sh     # build the .so
pip install -e ".[dev]"                 # editable install + dev deps
pytest                                  # unit + integration + framework
pytest tests/callbacks tests/signals    # Go-runtime interaction suite
python bench/run.py --framework flask   # per-route RPS / latency
bash testing/ftw/run.sh --framework flask --port 5000  # CRS corpus
```

See [`AGENTS.md`](./AGENTS.md) for the full contributor guide — security
checklist, release flow, what-to-touch-where.

## License

Apache-2.0. See [LICENSE](./LICENSE).
