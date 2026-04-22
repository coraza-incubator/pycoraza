# Flask example

pycoraza's WSGI middleware in front of a Flask app that implements the
shared HTTP contract.

## Install

```bash
# from the repo root
pip install -e ".[dev]"
pip install -r examples/flask_app/requirements.txt
```

## Run

```bash
python examples/flask_app/app.py
# listens on http://127.0.0.1:5000
```

Override the port with `PYCORAZA_PORT=6000 python examples/flask_app/app.py`.

## Try it

```bash
curl http://127.0.0.1:5000/                     # {"ok":true,"name":"flask"}
curl http://127.0.0.1:5000/search?q=hello       # {"q":"hello","len":5}
curl -X POST http://127.0.0.1:5000/echo \
     -H 'content-type: application/json' -d '{"msg":"hi"}'
```

## FTW mode

```bash
FTW=1 python examples/flask_app/app.py
```

Flips the WAF to paranoia=2 / block-mode and mounts a single `/*`
catch-all that echoes method + URL + headers + body back — the shape
go-ftw expects.
