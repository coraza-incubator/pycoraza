# Performance

Baseline numbers, methodology, and how to read them.

pycoraza is a WAF. A throughput drop on blocked traffic is expected
and correct — we count blocks, not raw RPS. This page explains the
measurement approach and what the numbers mean.

## Headline numbers

**TODO — measured on the first green `bench.yml` run.** Until then,
these are placeholders. Do not quote them in production capacity
planning.

| Framework  | p50 latency | p95 latency | p99 latency | RPS (happy path) | RPS (attack mix) |
|-----------:|------------:|------------:|------------:|-----------------:|-----------------:|
| Flask      | TODO ms     | TODO ms     | TODO ms     | TODO             | TODO             |
| FastAPI    | TODO ms     | TODO ms     | TODO ms     | TODO             | TODO             |
| Starlette  | TODO ms     | TODO ms     | TODO ms     | TODO             | TODO             |

Happy-path traffic is 1KB JSON GETs that do not match any CRS rule.
Attack-mix traffic is 50/50 clean and malicious (SQLi, XSS, path
traversal) — all malicious requests must be blocked.

Pinned baselines live in `bench/baselines/*.json` once the workflow
has populated them. The `bench.yml` workflow gates regressions: a
≥10% drop in RPS or a ≥20% increase in p99 fails the run.

## Methodology

### wrk (per-route)

`bench/run.py` drives `wrk` against each adapter's example app. Per-
route means "one HTTP method + one URL pattern at a time, no rule
matches, no body" — this is the best-case throughput upper bound for
pycoraza.

```bash
python bench/run.py --framework flask
python bench/run.py --framework fastapi
python bench/run.py --framework starlette
```

Defaults: 30s run, 4 threads, 200 connections, keep-alive on. No
warm-up accepted — the first 5s are discarded.

### k6 (attack mix)

`bench/k6_run.py` runs a mixed workload via `k6`: clean requests,
SQLi payloads, XSS payloads, path-traversal payloads, and oversize
payloads. It records two numbers side by side:

- `blocked_attacks` — must be ≥ number of attack requests sent.
- `missed_attacks` — must be 0. Any non-zero value is a security bug.

A performance change that increases RPS but drops `blocked_attacks`
is a regression, not an optimization. The k6 runner fails the
workflow on any non-zero `missed_attacks`.

```bash
python bench/k6_run.py --framework flask
```

### Hardware disclosure

Numbers in `bench/baselines/*.json` are recorded under the GitHub
Actions `ubuntu-latest` runner:

- 4 vCPU, 16 GB RAM (AMD EPYC-class, variable by allocation).
- `linux/amd64`.
- Python 3.13, Go 1.25, libcoraza at the tag pinned in
  `native/version.txt`.

Local numbers will differ. The CI numbers exist for regression
gating, not absolute capacity planning. When you need a production
capacity number, rerun `bench/run.py` on your own hardware under your
own config.

### Default config

The benchmark suites run with:

- `mode=ProcessMode.BLOCK`.
- `recommended(paranoia=1)` CRS profile.
- `inspect_response=False`.
- Default static-asset bypass.
- No custom `on_block` handler (default JSON block response).

Flipping `inspect_response=True` or raising paranoia roughly doubles
per-request work. Benchmark with the config you'll run in
production.

## How baselines are set

`bench/baselines/*.json` is not hand-written. The weekly
`bench.yml` workflow:

1. Runs `bench/run.py` and `bench/k6_run.py` against each framework.
2. Commits the resulting JSON to `bench/baselines/` via a PR.
3. A human reviewer confirms the numbers match expectations and
   merges.

New baselines are accepted when:

- Throughput increased and block rate didn't drop.
- OR an intentional behavior change justifies a throughput drop
  (e.g. a new phase got enabled).

Throughput drops without a documented reason are rejected; the PR
that caused the drop has to be fixed or reverted.

## Security > performance

Quoting [`../AGENTS.md`](../AGENTS.md) and
[`./threat-model.md`](./threat-model.md):

> Never sacrifice security for performance unless the trade-off is
> explicit, controlled, and opt-in.

Concretely:

- Throughput on **clean** traffic is the number we optimize.
- Throughput on **attack** traffic will always be lower — the WAF is
  spending CPU cycles inspecting and rejecting. That's the job.
- A "faster" variant of pycoraza that raises `missed_attacks` above
  zero is a bug. We don't ship those.
- Any opt-in that lets you trade security for throughput (a higher
  `inbound_anomaly_threshold`, `inspect_response=False`, a narrower
  skip predicate) is documented where it lives.

## Running benchmarks locally

```bash
# Per-route baseline.
python bench/run.py --framework flask

# Mixed attack workload.
python bench/k6_run.py --framework flask
```

Both expect the example apps in `examples/` to be runnable and a
`libcoraza.so` available on the loader path. Build libcoraza first
if you haven't:

```bash
git submodule update --init
./native/scripts/build-libcoraza.sh
pip install -e ".[dev,flask,fastapi]"
```

See `bench/run.py` and `bench/k6_run.py` for the exact command-line
surface — they support `--duration`, `--connections`, `--threads`,
and per-framework port overrides.

## See also

- [`./threat-model.md`](./threat-model.md) — why security beats
  throughput.
- [`./flask.md`](./flask.md), [`./fastapi.md`](./fastapi.md),
  [`./starlette.md`](./starlette.md) — production deployment notes,
  including worker sizing.
- [`./crs-profiles.md`](./crs-profiles.md) — how paranoia level and
  anomaly thresholds affect per-request work.
