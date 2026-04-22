# pycoraza-shared-example

The canonical HTTP contract implemented by every pycoraza example app.

Mirrors `coraza-node/examples/shared`: same route matrix, same FTW
toggle, same sample PNG. Each adapter (`flask_app`, `fastapi_app`,
`starlette_app`) imports `pycoraza_shared` and renders the returned
`HandlerResult` objects using its own response primitives.

## Install

The example apps expect `pycoraza_shared.py` to sit on the Python path.
The simplest way:

```bash
# from the repo root
pip install -e ".[dev]"        # pycoraza itself (editable)
pip install -e examples/shared  # the shared contract helper
```

Alternatively, run any example with `PYTHONPATH=examples/shared`.

## FTW mode

Set `FTW=1` in the environment to switch every adapter to paranoia=2,
block-mode, and a single catch-all echo route suitable for go-ftw.

## API surface

- `routes()` — list of `RouteSpec(method, path, name)` tuples.
- `ftw_mode_enabled(env=None)` — returns `True` when `FTW=1`.
- `ftw_echo_handler(request_like)` — builds the FTW echo response.
- `crs_profile(ftw)` — returns the SecLang rules string.
- Per-route handlers: `root`, `healthz`, `search`, `echo`, `upload`,
  `image`, `user`.
- `SAMPLE_PNG` — 1x1 transparent PNG bytes.
