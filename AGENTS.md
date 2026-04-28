# AGENTS.md — contributor & agent guide for pycoraza

This file is the single source of truth for how to work in this repo. It's
written for both humans and AI coding agents. `CLAUDE.md` and
`.github/copilot-instructions.md` intentionally just point here so there's
one canonical doc to keep current.

## What this project is

OWASP Coraza WAF packaged as a Python-native SDK. The Coraza engine (Go)
is built into `libcoraza.so` (a C shared library via `go build
-buildmode=c-shared` with a SWIG-compatible C API). pycoraza ships a
small cffi extension that links against `libcoraza` and exposes Python
bindings. Framework middleware (Flask, FastAPI, Starlette) wraps a
small core.

Nothing in this repo is shippable without the compiled `libcoraza.so`
artifact. Build it with `./native/scripts/build-libcoraza.sh` before
running anything else.

## Repository map

```
native/                         C binding & build helpers
  coraza_cdef.h                 curated C declarations cffi reads
  build_ffi.py                  hatchling build hook; drives cffi compile
  version.txt                   pinned libcoraza + CRS tag
  libcoraza/                    git submodule of corazawaf/libcoraza
  scripts/
    build-libcoraza.sh          builds libcoraza.so into LIBCORAZA_PREFIX

src/pycoraza/
  abi.py                        pythonic wrapper over the C ABI
  waf.py                        WAF class (rules + mode + logger)
  transaction.py                per-request Transaction class
  pool.py                       WAFRef — thin per-process WAF reference (see docs/scaling.md); `WAFPool` is a deprecated alias.
  skip.py                       shared static-asset bypass
  logger.py                     Logger protocol + default + silent loggers
  types.py                      dataclasses: Interruption, MatchedRule, etc
  _signals.py                   Go signal-handler isolation helpers
  coreruleset/                  CRS profile helpers + bundled rules
  flask/                        WSGI middleware
  starlette/                    ASGI middleware (primary)
  fastapi/                      thin re-export of pycoraza.starlette

tests/                          unit + integration + framework + callbacks + signals
examples/                       shared HTTP contract + three runnable demos
bench/                          wrk and k6 runners
testing/ftw/                    go-ftw corpus runner + overrides
docs/                           site + threat model + per-framework guides

.github/workflows/
  ci.yml                        build libcoraza + matrix test
  wheel-smoke.yml               install fresh wheel into clean venv,
                                boot each adapter, probe 200/403/403
  release.yml                   cibuildwheel + PyPI publish on tag
  ftw.yml                       CRS corpus against each adapter
  bench.yml                     weekly k6 regression
  docs.yml                      GitHub Pages deploy
  upstream-bump.yml             poll libcoraza + CRS releases
  news-check.yml                enforce towncrier fragment on publishable PRs
```

## Priority order

**Security > Performance.** Always. This is a WAF — if it doesn't
correctly block attacks, throughput is irrelevant. Rules that follow:

- **Never sacrifice security for performance unless the trade-off is
  explicit, controlled, and opt-in.** An env var the user consciously
  flips is acceptable; a silent fast-path that drops detections is not.
- **Fail closed on WAF errors.** If the WAF throws, crashes, or can't
  evaluate a request, the default MUST be to block
  (`on_waf_error="block"` in adapters). Fail-open is opt-in for
  availability-critical deployments and must be explicit.
- **Any perf change must measure block rate, not just RPS.** The
  `bench/k6_run.py` scenario counts `blocked_attacks` separately from
  throughput. A throughput gain that drops the block rate is a bug,
  not an optimization.
- **Default to stricter.** Every bypass-shaped defensive check must
  keep the request flowing into the WAF even when data is oversized.
  Never raise into a path that a framework might catch-and-continue.

See `docs/threat-model.md` for the threat model, known caveats
(ReDoS, Unicode case-insensitive, UTF-8 encoding, Go-runtime signals),
and the fail-closed checklist.

## Mandatory security checks (every change)

Every commit — perf tuning, refactor, new feature, doc, build change,
bump, anything — must include an explicit security-impact check. No
exceptions. Answer these five questions in the commit message or PR
description. If the answer to any is "I don't know," stop and
investigate.

1. **What's the security impact?** State it plainly: "no impact", "may
   bypass detection under condition X", "narrows an existing exposure",
   "adds a new code path attackers can reach", etc.
2. **Does any new code path handle an exception an attacker could
   force?** Follow every `except:` upward. Does the catch re-raise,
   log, or continue? If continue, is the request still evaluated by
   the WAF or does it reach the handler unfiltered? Raising into a
   framework's `except BaseException` fast path is a bypass.
3. **Does it change what Coraza sees?** Encoding changes, truncation,
   filtering, normalization, caching — any of these can make Coraza
   evaluate a different input than what the attacker sent. Confirm
   behavioral equivalence or document the gap.
4. **Does it change when rules fire?** Skipping a phase, reordering
   calls, batching, short-circuiting — anomaly-score rules (like CRS
   `949110`) must reach their evaluation point. Phase 2 always runs,
   even on body-less verbs.
5. **Are the defaults secure?** New option? Default must be the strict
   choice. New fast-path? Default off, opt-in via env var or config.

**How to verify:**
- `python bench/k6_run.py --framework flask` → `missed_attacks` must
  be 0. Any gap is a bypass.
- `pytest` — coverage gates enforced (see below).
- Changes to request flow (`src/pycoraza/transaction.py`,
  `src/pycoraza/abi.py`, adapter `__init__.py`): add an attack-shaped
  scenario in `tests/<framework>/test_scenarios.py`.

## Architectural invariants

1. **One C ABI.** All adapters go through `src/pycoraza/abi.py`.
   Never call libcoraza directly from an adapter. If an adapter needs
   something new, teach `abi.py` first.
2. **Go runtime landmines.** libcoraza is
   `go build -buildmode=c-shared`. This means:
   - **Signals**: Go installs its own SIGSEGV/SIGBUS/SIGPROF/SIGURG
     handlers on library init. Import `pycoraza` *before* any custom
     `faulthandler.enable()` or signal-handler install. Document this
     loudly for users.
   - **GIL across callbacks**: `coraza_set_error_callback` fires from
     arbitrary Go goroutine OS threads. Every cffi callback
     trampoline must `PyGILState_Ensure` / `Release`. This is not
     optional.
   - **Double-init**: Go's runtime cannot be initialized twice. The
     library is loaded exactly once per process. `importlib.reload`
     is not supported; use a new process.
3. **Transactions are per-request.** Cheap to create. Always close at
   end of response. `process_logging` + `close`.
4. **Body phase is opt-in.** Every adapter gates bodies on
   `tx.is_request_body_accessible()` / `tx.is_response_body_processable()`.
5. **Short-circuit on engine off.** First thing every adapter does
   after `new_transaction()` is check `tx.is_rule_engine_off()`.
6. **Static/media bypass is first-class.** The `skip` option on every
   adapter defaults to bypassing images, CSS, JS, fonts, common static
   prefixes. See `src/pycoraza/skip.py`.
7. **Default mode is `DETECT`, not `BLOCK`.** Safer first-run.
8. **`inspect_response` is off by default.** Doubles per-request work;
   enable only for response-side rules.
9. **WAF can be shared across threads.** Go's runtime handles
   scheduling. Within one process, one WAF is safe.

## The C ABI

Read `native/coraza_cdef.h` — it mirrors libcoraza's public C header
exactly. Summary:

- Return codes: `0` = ok, `1` = interrupted, `-1` = error.
- Handles (`coraza_waf_t *`, `coraza_transaction_t *`, ...) are
  opaque; never dereference them from Python.
- Request flow: `coraza_process_connection` →
  `coraza_add_request_header`* → `coraza_process_uri` →
  `coraza_process_request_headers` → `coraza_append_request_body`* →
  `coraza_process_request_body` → response phase → `coraza_process_logging` →
  `coraza_free_transaction`.
- When the C ABI changes in upstream libcoraza, bump the pinned tag
  in `native/version.txt` and update `coraza_cdef.h` to match.

## Build & test

### libcoraza

```sh
git submodule update --init
./native/scripts/build-libcoraza.sh
# Produces libcoraza.so under $LIBCORAZA_PREFIX (default: build/libcoraza).
```

### Python

```sh
pip install -e ".[dev]"
pytest
pytest tests/callbacks tests/signals    # Go-runtime landmine suite
pytest --cov                            # enforces coverage gates
ruff check . && mypy                    # lint + types
python bench/run.py --framework flask   # per-route bench
python bench/k6_run.py --framework flask
```

### Wheels

```sh
cibuildwheel --platform linux
# Produces wheels/pycoraza-0.x.y-cp3XX-manylinux_2_28_x86_64.whl
```

## Coverage expectations

- **Core** (`abi.py`, `waf.py`, `transaction.py`, `skip.py`,
  `logger.py`, `types.py`, `pool.py`): ≥95% lines, ≥90% branches.
- **Adapters** (`flask`, `starlette`, `fastapi`): ≥90% lines, ≥85% branches.
- **CRS profiles** (`coreruleset/_profiles.py`): 100% lines (pure
  string builders, no excuse for gaps).

Thresholds enforced by `pyproject.toml` and the `ci.yml` workflow.

## Testing layers, in order of strength

1. **Unit (pytest + fake ABI)** — every `src/pycoraza/*.py` module in
   isolation. Mock cffi handles.
2. **Integration (pytest + real libcoraza)** — covers the cffi
   wrapper end-to-end. Requires a built `libcoraza.so`.
3. **Callback / signal (pytest)** — priority-0 suite under
   `tests/callbacks/` and `tests/signals/`. Verifies GIL handling on
   Go-goroutine callback threads and faulthandler compatibility.
4. **Framework integration** — Flask `TestClient`, Starlette
   `TestClient`, httpx `AsyncClient`. Real middleware, fake WAF at
   the ABI edge.
5. **E2E** — example apps under gunicorn / uvicorn, real HTTP
   against them, assert blocking.
6. **FTW corpus** — go-ftw against each adapter, 100% pass rate.
7. **Benchmarks** — per-route (wrk) + mixed k6 workload. Every PR
   that changes request flow must run k6 locally and record numbers.

If you change the C ABI: all seven layers need touching. Start at
`native/coraza_cdef.h`, then `abi.py`, then fake ABI in tests, then
integration tests, then adapters.

### Wheel-smoke gate

`.github/workflows/wheel-smoke.yml` is the only CI lane that exercises
the **published-wheel install path** users hit with `pip install
pycoraza`. Editable installs (`pip install -e .`) hide whole classes
of packaging regressions — wrong package data, missing rules, missing
`_bindings/*.so`, broken extras. The smoke job builds a fresh sdist +
wheel, installs the wheel into a clean consumer venv on a separate
runner, boots each adapter (flask under gunicorn, fastapi/starlette
under uvicorn) with `PYCORAZA_WAF=on PYCORAZA_MODE=block FTW=0`, and
runs a 200/200/403/{200|403}/403 probe matrix (benign, XSS, SQLi-in-
body, SQLi). Logic is in `bench/wheel_smoke.sh` so devs can repro:

```sh
LIBCORAZA_PREFIX=$(pwd)/build/libcoraza bash bench/wheel_smoke.sh dist/pycoraza-*.whl
```

The smoke wheel is NOT auditwheel-repaired — `libcoraza.so` is loaded
via `LD_LIBRARY_PATH` from the build artifact. When you flip on
auditwheel-repair in the smoke build, drop the `LIBCORAZA_PREFIX`
requirement from the helper and the workflow's smoke job.

## Go-runtime signal policy

The only code that deliberately pokes at Go's signal table is
`src/pycoraza/_signals.py`. It:

- documents every Go-installed signal and the order of install,
- provides a helper to re-install Python's `faulthandler` after
  importing `pycoraza`,
- emits a one-line WARN log if it detects Python's SIGINT handler
  has been displaced after import.

Do not install custom signal handlers from adapter code. If a user
needs to, document the correct order (import pycoraza → install
handlers) in the middleware docstring.

## Coding style

- **No comments unless they explain WHY.** Identifiers carry the WHAT.
- **No runtime type validation at internal boundaries.** Trust
  dataclasses; only validate at user-facing edges (middleware entry,
  ABI marshaling).
- **No back-compat shims or feature flags.** Change the code directly
  — we're pre-1.0.
- **Prefer editing existing files** over adding new ones.
- **No emojis in code or markdown** unless the user asks.

## Release flow

### Branches

- `develop` — integration branch. Every PR lands here first. CI runs
  (lint, typecheck, unit, integration, framework, callback, signal
  suites). No PyPI publish.
- `main` — stable line. Merges into `main` only after `develop` is
  green and a maintainer opens a PR from `develop` → `main`.

### The very first release

0.1.0 is cut by hand: tag `v0.1.0`, the `release.yml` workflow runs
cibuildwheel + sdist build, verifies wheels, publishes to PyPI via
trusted publishing (OIDC).

### Every release after that

- Any PR touching `src/pycoraza/**` or `pyproject.toml` must include a
  `news/*.md` towncrier fragment. `news-check.yml` enforces this.
- Tagging a `vX.Y.Z` on `main` triggers `release.yml`: it runs
  `towncrier build --version X.Y.Z --yes` to update CHANGELOG.md,
  builds wheels, publishes to PyPI, creates a GitHub release.
- **patch** — bug fix, no public API change.
- **minor** — new option, new API, behavior change, security-impacting
  fix worth callouts.
- **major** — reserved. Pre-1.0 we use minor for breaking too; we exit
  0.x by tagging `1.0.0` when the API surface is stable.

### Do not

- Do not run `python -m build && twine upload` manually. All publish
  goes through `release.yml`.
- Do not merge a `src/pycoraza/**` change without a news fragment. If
  the change legitimately should not release, commit an empty fragment
  under `news/+<slug>.misc.md` with `no user-visible change`.

## FTW (CRS regression corpus)

We drive the OWASP CRS `go-ftw` test corpus against every adapter.
The goal is a fast-feedback regression signal whenever the engine or
the SecLang CRS profile in `pycoraza.coreruleset` changes.

How the pieces fit:

- Every example app reads `FTW=1` from the env. When set, it mounts
  a single echo-all route, runs CRS in `block` mode at paranoia 2,
  and otherwise preserves its normal shape. Shared logic lives in
  `examples/shared/pycoraza_shared.py` (`ftw_mode_enabled`, `ftw_echo`).
- `testing/ftw/run.sh` is the runner. It installs `go-ftw` pinned
  via `GO_FTW_VERSION`, fetches the CRS corpus at `CRS_TAG` (read
  from `native/version.txt`), boots the selected adapter under
  `FTW=1`, runs `go-ftw run` with shared overrides, enforces a
  pass-rate threshold.
- `testing/ftw/ftw-overrides.yaml` is shared; entries carry tagged
  justifications (`[flask-*]`, `[fastapi-*]`, `[starlette-*]`,
  `[upstream-coraza]`, `[engine]`).
- `.github/workflows/ftw.yml` runs a matrix over
  `[flask, fastapi, starlette]` with `fail-fast: false`. 100%
  threshold for all.

If you add a rule-family override: include the tag and a one-line
reason. Overrides without a tag are reviewer-rejected — the audit
trail is how we know whether a failure is framework noise or an
engine regression.

## Known issues

1. **Local libcoraza build without Go 1.25**: older Go versions may
   produce a `.so` whose `getrandom` symbol version is too new for
   `manylinux_2_28`. Use `./native/scripts/build-libcoraza.sh` which
   pins Go.
2. **faulthandler after `import pycoraza`**: installing faulthandler
   or a custom SIGSEGV handler *after* importing pycoraza can
   displace Go's handlers. See `docs/threat-model.md`.

## What to change, and where

| If you're changing… | Touch |
|---|---|
| libcoraza C ABI | `native/coraza_cdef.h` + `native/version.txt` + `src/pycoraza/abi.py` + tests |
| New WAF config option | `src/pycoraza/types.py` + `src/pycoraza/waf.py` + adapters |
| Framework adapter behavior | `src/pycoraza/<adapter>/__init__.py` + its tests |
| Static-file bypass logic | `src/pycoraza/skip.py` (NOT per-adapter) |
| CRS profile preset | `src/pycoraza/coreruleset/_profiles.py` |
| CI / release workflow | `.github/workflows/*.yml` |
| FTW corpus / overrides | `testing/ftw/*` + `.github/workflows/ftw.yml` |
| Docs an agent will read | THIS FILE. Not a new doc. |
