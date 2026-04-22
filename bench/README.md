# pycoraza benchmarks

Two runners live here. Both boot one of the `examples/<framework>_app/app.py`
example apps, drive real HTTP traffic, and compare throughput and latency with
the WAF on vs off. `bench/baselines/<framework>.json` pins the numbers the
weekly `bench.yml` CI workflow regresses against.

## Runners

### `bench/run.py` — per-route (wrk)

Shells out to `wrk` against each of the seven canonical routes in turn, parses
the `Requests/sec` and latency percentiles from wrk's stdout, and prints a
markdown table. Use this when you want to see which specific endpoint got
faster or slower.

```sh
python bench/run.py --framework flask
python bench/run.py --framework fastapi --duration 15 --connections 100
python bench/run.py --framework starlette --waf off --json /tmp/off.json
```

Typical output:

```
## pycoraza bench (flask, WAF=on)

duration=10s connections=50 threads=2 port=8001

| Route | RPS | p50 | p95 | p99 | non-2xx |
|---|---:|---:|---:|---:|---:|
| GET /            | 4,812 | 8.10ms | 18.20ms | 24.00ms | 0 |
...
```

Compare two runs side-by-side by diffing the JSON dumps
(`--json waf_on.json` + `--json waf_off.json`).

### `bench/k6_run.py` — mixed traffic (k6)

Boots the app, runs `k6 run bench/k6/mixed.js` with a ~70/30 mix of benign
traffic and attack payloads (SQLi, XSS, path traversal, command injection),
parses k6's summary JSON, and prints a single compact summary. Use this
whenever you change request-flow code. **Fails the run with exit 1 if
`missed_attacks > 0`** — a missed attack is a WAF regression.

```sh
python bench/k6_run.py --framework flask
python bench/k6_run.py --framework fastapi --vus 100 --duration 30s
python bench/k6_run.py --framework starlette --json /tmp/mixed.json
```

## Prerequisites

The Python runners use only the standard library, but the underlying load
generators are system binaries:

- `wrk` — `brew install wrk` (macOS) or `apt install wrk` (Debian/Ubuntu).
- `k6`  — https://k6.io/docs/get-started/installation/ (prebuilt binaries for
  all common OSes).

The runners exit with code `2` and a clear message if either binary is
missing.

## Interpreting results

### RPS and latency

Compare WAF=on vs WAF=off on the **same machine, in the same run**. Absolute
numbers across hardware are not comparable — `baselines/<framework>.json`
records the hardware snapshot that produced the pinned numbers so the weekly
CI can detect real regressions without flagging noise from new runners.

### `missed_attacks > 0` — hard fail

The k6 mixed scenario tags each attack request. If the WAF is engaged and any
of those requests returns `2xx`, the counter increments. `bench/k6_run.py`
exits non-zero in that case.

This is the heart of the "Security > Performance" principle from `AGENTS.md`:

> Never sacrifice security for performance unless the trade-off is explicit,
> controlled, and opt-in. Any perf change must measure block rate, not just
> RPS. A throughput gain that drops the block rate is a bug, not an
> optimization.

A PR that improves RPS by 30% but misses even one attack in the mixed
scenario must be investigated before landing — no exceptions.

### `PYCORAZA_WAF=off` environment variable

Both runners pass `PYCORAZA_WAF=on|off` to the booted app. Example apps read
this env var to decide whether to mount the middleware. If an app hasn't been
updated yet to honor the variable, the "off" leg will still run with WAF
engaged — the numbers will be honest but the WAF-off comparison becomes
meaningless. Fix the app rather than working around it here.

## Updating a baseline

After a legitimate improvement lands:

1. Run both benches on the reference hardware you want to pin to (record it
   in the file).
2. Open `bench/baselines/<framework>.json` and set:
   ```json
   {
     "adapter": "flask",
     "measured_at": "2026-04-22",
     "hardware": "GitHub ubuntu-22.04 x64, 4 vCPU, 16 GiB",
     "waf_off_rps": 12500,
     "waf_on_rps": 4900,
     "p99_ms_waf_on": 24.2,
     "comment": "bump after flask adapter body-phase streaming optimization (#123)"
   }
   ```
3. Include the `news/+<slug>.perf.md` towncrier fragment and the bench output
   in the PR.
4. `bench.yml` will use the new baseline on the next weekly run.

Never lower a baseline without a matching note in the commit explaining why
the old number is no longer achievable on the reference hardware (e.g.
upstream libcoraza did an audit-friendly rewrite that legitimately costs N%).
