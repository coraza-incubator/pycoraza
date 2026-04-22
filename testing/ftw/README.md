# FTW — OWASP CRS regression corpus

`go-ftw` is the OWASP Core Rule Set regression test runner
(https://github.com/coreruleset/go-ftw). It replays a corpus of HTTP
attack tests against a running WAF-protected server and reports pass /
fail per test. This directory wires go-ftw up against each of
pycoraza's example applications (flask, fastapi, starlette) so we can
guard against drift between the CRS rules we ship and the rules our
WAF-integrated examples actually enforce.

## How to run locally

You need `bash`, `curl`, `tar`, `python3`, and a working `go`
toolchain (the runner uses `go install` to fetch `go-ftw` at the
version pinned in `native/version.txt`). Install `jq` for nicer JSON
parsing — it is optional.

From the repo root:

```sh
bash testing/ftw/run.sh --framework=flask
bash testing/ftw/run.sh --framework=fastapi --port=5001
bash testing/ftw/run.sh --framework=starlette --threshold=98
```

Supported flags:

| Flag                   | Default                                    | Purpose                                                           |
|------------------------|--------------------------------------------|-------------------------------------------------------------------|
| `--framework=<name>`   | required                                   | `flask`, `fastapi`, or `starlette`.                               |
| `--port=<N>`           | flask 5000, fastapi 5001, starlette 5002   | Port the example app binds to.                                    |
| `--threshold=<PCT>`    | `100`                                      | Fail the run when pass rate drops below this percent.             |
| `--crs-tag=<tag>`      | `CRS_TAG` from `native/version.txt`        | Pin the CRS corpus to a specific release tag.                     |
| `--go-ftw-version=<t>` | `GO_FTW_VERSION` from `native/version.txt` | Pin the go-ftw binary to a specific release tag.                  |
| `--skip-boot`          | off                                        | Don't start the example app; assume something is already on PORT. |

The runner:

1. Resolves `CRS_TAG` and `GO_FTW_VERSION` from `native/version.txt`
   (or the matching CLI flag / env var).
2. Installs `go-ftw` via `go install` into
   `testing/ftw/build/gobin/`, skipping if the binary is already there.
3. Downloads the OWASP CRS corpus tarball at `${CRS_TAG}` into
   `testing/ftw/build/crs/v<version>/`, extracting to
   `<extracted>/tests/regression/tests/`.
4. Boots `examples/<framework>_app/app.py` with
   `FTW=1 PYCORAZA_PORT=<port>`, captures the PID, and waits up to
   `BOOT_TIMEOUT` seconds (default 60) for `/healthz` to return a
   2xx/3xx.
5. Concatenates `ftw-overrides.yaml` with
   `ftw-overrides-<framework>.yaml` into a per-run combined file.
6. Runs `go-ftw run --dir <corpus> --overrides <combined>
   --connect-timeout 5s --read-timeout 10s --output json` and writes
   the result to `testing/ftw/build/ftw-result-<framework>.json`.
7. Parses the JSON and exits non-zero if the pass rate falls below
   `--threshold`.

The background example server is killed on script exit via a `trap`,
so Ctrl-C and errors both clean up the port.

## Override tags

Every entry in the overrides YAMLs MUST carry a tag prefix in its
`reason` field. This keeps the overrides auditable: a reviewer can
tell at a glance which layer is responsible for a failing CRS test.

| Tag                 | Meaning                                                                                                                                                                                             | Lives in                              |
|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| `[upstream-coraza]` | A known gap in the upstream `corazawaf/coraza` engine. The same test fails against `coraza-caddy` / `coraza-node` at the same CRS tag. Tracked in the upstream coraza repo.                         | `ftw-overrides.yaml`                  |
| `[engine]`          | A limitation in pycoraza's native bindings layer (ctypes/SWIG marshalling, transaction lifecycle, etc.) rather than in the framework integration. Cite the open issue in the reason when adding one. | `ftw-overrides.yaml`                  |
| `[flask-*]`         | Something Flask / Werkzeug does differently from the CRS/Apache baseline (e.g. `[flask-wsgi]`, `[flask-routing]`, `[flask-parser]`). The reason MUST cite what Flask changes.                        | `ftw-overrides-flask.yaml`            |
| `[fastapi-*]`       | Something FastAPI / Uvicorn does differently (e.g. `[fastapi-asgi]`, `[fastapi-routing]`). The reason MUST cite what FastAPI changes.                                                                | `ftw-overrides-fastapi.yaml`          |
| `[starlette-*]`     | Something Starlette does differently (e.g. `[starlette-middleware]`, `[starlette-parser]`). The reason MUST cite what Starlette changes.                                                             | `ftw-overrides-starlette.yaml`        |

Adding an override without a tag, or with a non-specific reason like
"flaky" / "fails locally", is reviewer-rejected. If the real fix is
an engine or framework bug, file the tracking issue first and reference
it in the reason. Masking a CRS failure with `forcepass`-style
overrides without a cited cause is treated as a security regression.

## Files

| File                            | Purpose                                                                 |
|---------------------------------|-------------------------------------------------------------------------|
| `run.sh`                        | The driver. Bash + `set -euo pipefail`.                                 |
| `ftw-overrides.yaml`            | Shared overrides applied to every framework leg.                        |
| `ftw-overrides-flask.yaml`      | Flask-only overrides (may be empty).                                    |
| `ftw-overrides-fastapi.yaml`    | FastAPI-only overrides (may be empty).                                  |
| `ftw-overrides-starlette.yaml`  | Starlette-only overrides (may be empty).                                |
| `build/` (gitignored)           | go-ftw binary, CRS cache, per-run logs, combined overrides, JSON result. |

## Making run.sh executable

The repo ships `run.sh` with executable intent but a fresh checkout on
a case-sensitive filesystem may require:

```sh
chmod +x testing/ftw/run.sh
# or, to record the bit in git:
git update-index --chmod=+x testing/ftw/run.sh
```

Invoking it via `bash testing/ftw/run.sh ...` also works regardless
of the executable bit.
