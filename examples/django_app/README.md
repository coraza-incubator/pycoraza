# django_app — pycoraza example

Minimal Django project exercising `pycoraza.django.CorazaMiddleware`
over the shared HTTP contract.

## Run

```sh
# dev: Django's runserver (OK for smoke-testing)
PYCORAZA_PORT=5003 python manage.py runserver 127.0.0.1:5003

# prod-shaped: gunicorn (strict parser, matches FTW runner)
PYCORAZA_PORT=5003 gunicorn \
    --workers 4 --worker-class sync \
    -b 127.0.0.1:5003 \
    --chdir examples/django_app \
    django_app.wsgi:application
```

## Env knobs

| Variable | Default | Effect |
|---|---|---|
| `PYCORAZA_PORT` | 5003 | listening port |
| `PYCORAZA_WAF` | on | set `off` to bypass middleware entirely (for waf-off baselines) |
| `PYCORAZA_MODE` | — | `block` or `detect`; default is `DETECT` unless `FTW=1` |
| `FTW` | — | `FTW=1` flips to `paranoia=2` + `ProcessMode.BLOCK` and mounts the single `/*` echo route |

## Hit it

```sh
curl -s http://127.0.0.1:5003/healthz                       # -> "ok"
curl -s "http://127.0.0.1:5003/search?q=hello"              # -> {"q":"hello","len":5}
curl -si "http://127.0.0.1:5003/search?q=<script>alert(1)"  # -> 403 in block mode
```
