# Starlette example

pycoraza's ASGI middleware in front of a Starlette app that implements
the shared HTTP contract.

## Install

```bash
# from the repo root
pip install -e ".[dev]"
pip install -r examples/starlette_app/requirements.txt
```

## Run

```bash
uvicorn examples.starlette_app.app:app --port 5002
# or
python examples/starlette_app/app.py
```

Override the port with `PYCORAZA_PORT=6002`.

## Try it

```bash
curl http://127.0.0.1:5002/                     # {"ok":true,"name":"starlette"}
curl http://127.0.0.1:5002/healthz              # ok
curl -X POST http://127.0.0.1:5002/echo \
     -H 'content-type: application/json' -d '{"msg":"hi"}'
```

## FTW mode

```bash
FTW=1 uvicorn examples.starlette_app.app:app --port 5002
```

Flips the WAF to paranoia=2 / block-mode and mounts a single
catch-all route that echoes method + URL + headers + body — the shape
go-ftw expects. Response-side inspection is enabled in this mode so
`RESPONSE-*` rules fire against the echoed body.
