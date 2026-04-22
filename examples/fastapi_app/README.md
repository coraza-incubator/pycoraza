# FastAPI example

pycoraza's ASGI middleware in front of a FastAPI app that implements
the shared HTTP contract.

## Install

```bash
# from the repo root
pip install -e ".[dev]"
pip install -r examples/fastapi_app/requirements.txt
```

## Run

```bash
uvicorn examples.fastapi_app.app:app --port 5001
# or
python examples/fastapi_app/app.py
```

Override the port with `PYCORAZA_PORT=6001`.

## Try it

```bash
curl http://127.0.0.1:5001/                     # {"ok":true,"name":"fastapi"}
curl http://127.0.0.1:5001/api/users/42         # {"id":"42"}
curl -X POST http://127.0.0.1:5001/upload \
     -H 'content-type: application/octet-stream' --data-binary @- <<<'hello'
```

## FTW mode

```bash
FTW=1 uvicorn examples.fastapi_app.app:app --port 5001
```

Flips the WAF to paranoia=2 / block-mode and mounts a single
catch-all route that echoes method + URL + headers + body — the shape
go-ftw expects. Response-side inspection is enabled in this mode so
`RESPONSE-*` rules fire against the echoed body.
