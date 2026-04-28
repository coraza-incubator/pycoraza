# Threat model

What pycoraza protects against, what it doesn't, and the Go-runtime
caveats that come from embedding libcoraza in a Python process.

This is the security-first companion to [`./quickstart.md`](./quickstart.md)
and [`../AGENTS.md`](../AGENTS.md). If you're changing code in this repo
or making a deployment decision, read this first.

## Priority

1. **Correctness** — the WAF must evaluate every request against every
   configured rule and block what CRS (or your custom rules) says to
   block.
2. **Availability** — the WAF must not crash the host process or loop
   forever.
3. **Performance** — throughput and latency.

Never trade (1) for (3) silently. An opt-in, clearly-documented knob
that lets a user accept a risk (e.g. `inspect_response=False` to skip
phase 4) is fine. A perf optimization that happens to skip some
attacks without warning is a bug.

## Trust model

The WAF sits inside the application process. Trust assumptions:

- The Python interpreter and its host OS are trusted. Attackers
  interact via HTTP requests, not by running code in the same process.
- `libcoraza.so` is trusted. We compile it from a pinned upstream tag
  (`native/version.txt`), vendor it into wheels, and sign the wheel on
  release.
- The CRS rule set is trusted. We embed a pinned release tag.
- Any threads and asyncio tasks spawned inside the same process are
  trusted (shared memory semantics).
- The host kernel is trusted for resource-exhaustion protection — we
  don't try to defend against a co-tenant DoS'ing the box.

We protect against:

- Crafted HTTP requests designed to bypass detection (SQLi, XSS, LFI,
  RCE, deserialization, path traversal, and anything else CRS knows
  about).
- Crafted requests designed to exploit WAF implementation bugs
  (oversize fields, malformed UTF-8, unusual methods) to reach
  handlers unfiltered.
- WAF crashes and panics becoming silent bypasses — the adapters fail
  closed by default (see below).

We don't protect against:

- ReDoS inside SecLang `@rx` patterns (see caveat below).
- Denial of service from legitimately large or numerous requests. Use
  a rate limiter upstream; Coraza is not a rate limiter.
- Handler-level bugs that succeed despite detection. The WAF raises
  the bar; it isn't a substitute for secure code.
- Supply-chain compromise of libcoraza or CRS upstream. Pin-and-audit
  is our only control there.

## Fail-closed defaults

pycoraza ships with fail-closed defaults. You must consciously opt out
of any of them; the library will not do it for you.

- `on_waf_error="block"` — if the adapter cannot instantiate a
  transaction or a WAF call raises `CorazaError`, the request returns
  a 500 response. Flip to `"allow"` only when you've weighed
  availability over security and written it down. You can also pass a
  callable for circuit-breaker behavior — see "Circuit-breaker policy"
  below.
- `mode=ProcessMode.DETECT` — the default out of `WAFConfig`. You
  must explicitly set `ProcessMode.BLOCK` to enforce rules. This is
  intentional: a wrong rule in detect mode logs; a wrong rule in block
  mode takes your service down.
- `inspect_response=False` — phase 3+4 (response headers, response
  body) are skipped unless you enable them. This is a throughput
  choice, not a security-correctness choice. Enable when you have
  rules that need the response body. With `inspect_response=True`
  the adapters now BUFFER the response and ENFORCE a phase-3/4
  block when `mode=BLOCK` — earlier versions ran the rules in
  monitor-only mode and let the upstream response through even when
  a response-side CRS rule disrupted. The Starlette / FastAPI
  middleware additionally exposes `inspect_streaming=False`; flip to
  `True` only for SSE / chunked downloads where buffering is
  impossible, and accept that disruptive response-side rules cannot
  be enforced in that mode.
- Adapter error paths never swallow `CorazaError`. If `new_transaction`
  fails, the request is dropped by `_handle_waf_error`. Adapters do
  not silently pass the request through. Flask additionally treats
  any exception from the WSGI body read (slow / broken client) as a
  WAF error so `on_waf_error` policy applies and the transaction is
  closed deterministically. Starlette / FastAPI's
  `on_waf_error="allow"` resolves correctly: the buffered request
  body is replayed to the downstream app via the receive channel.

## Go-runtime caveats

libcoraza is `go build -buildmode=c-shared`. When Python loads the
shared library, Go's runtime initializes inside the Python process.
That has three consequences every operator needs to know about.

### Signal-handler displacement

Go installs its own handlers for these signals on library init:
`SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGPIPE`, `SIGURG`, `SIGPROF`,
`SIGXFSZ`. If your application has already installed handlers for any
of these, Go will displace them when `pycoraza` is imported.

See `src/pycoraza/_signals.py` for the canonical list and
`snapshot_handlers()` / `audit_after_load()` helpers.

**Common symptoms:**

- `faulthandler` stops printing tracebacks on segfault.
- A custom profiler that uses `SIGPROF` stops receiving samples.
- Long-running Python C extensions see unexpected `EINTR` (Go's
  async-preemption uses `SIGURG` in Go ≥ 1.14).

**Remediation:**

1. **Import `pycoraza` before `faulthandler.enable()` and before any
   `signal.signal(...)` calls.** pycoraza's `__init__.py` loads
   libcoraza at import time. Import order matters.
2. **Use `apply_asyncpreempt_mitigation()` or set `GODEBUG=asyncpreemptoff=1`**
   in the environment to disable Go's SIGURG preemption if it
   interferes with long-running embeddings or with C extensions that
   are not safe under `EINTR`.
3. **Audit with `snapshot_handlers()` / `audit_after_load()`** in
   startup code if you need a runtime warning when Go clobbers a
   handler you care about.

```python
import faulthandler
import pycoraza  # import FIRST so Go installs its handlers first
faulthandler.enable()  # now safe — we see both Go and Python panics
```

### cffi callback GIL contract

`coraza_set_error_callback` and similar callbacks fire from arbitrary
Go goroutine OS threads. These threads did not originate from Python;
they do not hold the GIL.

Every callback trampoline must wrap its body in
`PyGILState_Ensure` / `PyGILState_Release`. pycoraza's built-in
`abi.register_error_callback` does this for you. If you implement a
custom cffi callback against any libcoraza entrypoint, you must do the
same — otherwise you will get intermittent interpreter crashes under
load, because calling into CPython without the GIL corrupts reference
counts.

Concretely, with cffi's `@ffi.callback` decorator and `"python-api"`
mode, the generated trampoline does this automatically. With the
`"abi"` mode or hand-written ctypes trampolines, you are on your own.
Prefer pycoraza's `abi.register_error_callback` wrapper over rolling
your own.

### Double-initialization is not supported

Go's runtime is a process-wide singleton. It cannot be initialized
twice. As a consequence:

- `importlib.reload(pycoraza)` is not supported. Restart the process.
- Embedding pycoraza into a plugin host that `dlclose()`s its plugins
  is not supported. Python's C extension unload semantics are already
  fragile; combining with Go makes it worse.
- A test suite that tears down and re-imports pycoraza between tests
  will eventually corrupt memory. Our test suite uses per-test WAF
  instances and a long-lived library handle.

Rule of thumb: one pycoraza-importing process is one pycoraza lifetime.

## Fail-closed checklist

Use this to validate your deployment before turning block mode on.

- [ ] Adapter middleware catches `CorazaError` and falls through to
      `_handle_waf_error`. Verify by forcing a WAF error and
      confirming a 500 rather than a pass-through.
- [ ] `new_transaction` failure also fails closed. Verify by
      instantiating a WAF with invalid SecLang and confirming the
      first request returns 500, not 200.
- [ ] `on_waf_error` is `"block"` (the default). Explicitly in config
      so a future refactor can't change the default from under you.
- [ ] `mode` is `ProcessMode.BLOCK` in production. `DETECT` is
      log-only.
- [ ] `inspect_response=True` if you have response-side rules. If not,
      leave it off — enabling it without response-side rules is pure
      overhead.
- [ ] Static-asset bypass (`skip=...`) does not accidentally skip a
      dynamic route. Audit the default extensions and prefixes against
      your routing table.
- [ ] Custom `on_block` handlers still return a non-2xx status. The
      adapter will not override a 200 from a badly-written handler.
- [ ] `faulthandler.enable()` (if you use it) runs after
      `import pycoraza`.

Run `pytest tests/signals tests/callbacks` after any change that
touches adapter error handling. Those suites are the enforcement
mechanism for this checklist.

## Circuit-breaker policy for `on_waf_error`

`on_waf_error` accepts the literal strings `"block"` / `"allow"` (or
the `pycoraza.OnWAFError` enum), AND a callable of type
`pycoraza.WAFErrorPolicy`. The callable receives the raised exception
and the `RequestInfo` and must return the literal string `"block"` or
`"allow"`. Adapters invoke it ONLY on WAF errors — `CorazaError`
raised inside the middleware — never on rule-driven blocks.

A typical use: open the circuit (allow traffic) after a sustained
spike in WAF errors so an upstream blip doesn't take the service
offline, while still failing closed on the first few errors.

```python
class FailOnceThenAllow:
    def __init__(self) -> None:
        self.fail_count = 0

    def __call__(self, exc, req):
        self.fail_count += 1
        if self.fail_count > 5:  # persistent failures -> open the circuit
            return "allow"
        return "block"

CorazaMiddleware(app, waf=waf, on_waf_error=FailOnceThenAllow())
```

If the callable itself raises, or returns anything other than
`"block"` / `"allow"`, the adapter falls back to `OnWAFError.BLOCK` —
fail-closed posture extends to the policy callable. This is
deliberate: a buggy policy must not silently turn into a bypass.

## Skip predicate as a config knob

`pycoraza.skip.build_skip_predicate` is a **performance optimization,
not a security boundary.** Both the default static-asset bypass
(`/static/`, `/assets/`, `*.png`, `*.css`, ...) and any user-supplied
`SkipOptions` or callable cause Coraza to never see the request. There
is no WAF evaluation, no logging, no auditing. From the WAF's point of
view those requests do not exist.

The fail-closed default (`on_waf_error="block"`) only catches WAF
*errors* — `CorazaError` raised inside the middleware. It does not
second-guess a user-configured bypass. If your predicate returns
`True` on `path.startswith("/api")`, you have disabled the WAF for the
entire API surface, and pycoraza will obediently do exactly that.

Match semantics worth knowing about (full list in
`build_skip_predicate.__doc__`):

- The predicate sees the URL **path** only, never the query string.
- Extension matching is **case-insensitive** (both sides lowered).
- Compound extensions like `.tar.gz` are NOT a single token. Only the
  last `.<ext>` segment matches; the default tuple lists both `.tar`
  and `.gz` to cover the common case. To skip a specific file like
  `/dump.tar.gz`, add it to `SkipOptions.extra_paths` instead.

Audit your skip configuration against your routing table at every
release. A new dynamic handler mounted under `/static/` will be
silently bypassed; pycoraza cannot warn you about a request it never
saw.

## Known caveats

### ReDoS in SecLang `@rx`

SecLang's `@rx` operator uses Go's `regexp` package by default, which
is RE2-based (linear time, no catastrophic backtracking). This is
safer than PCRE-based engines.

**However:** CRS has historically shipped patterns that triggered
pathological behavior even on RE2 (exponential match time in corner
cases with long inputs). CVE history is public — check the CRS
changelog. Mitigation:

- Pin a known-good CRS tag (`native/version.txt` controls this).
- Monitor for rule evaluations exceeding your p99 latency budget and
  fingerprint the request that caused it.
- Upstream CRS `@rx` patterns have per-request input-length limits
  via `tx.arg_length` / `tx.arg_name_length` checks in phase 1. Keep
  those rules enabled.

pycoraza does not expose a per-request regex timeout. Go's `regexp`
does not support one at the engine level.

### Unicode case-insensitive matching

SecLang's `t:lowercase` transformation applies ASCII lowercasing
before case-insensitive `@rx` evaluation. Non-ASCII case folding
(Turkish dotted/dotless İ, German ß, etc.) is NOT applied.

**Implication:** an attacker encoding a payload in non-ASCII case
variations could evade a rule that assumed Unicode case folding.

**Mitigation:** CRS rules that depend on case-insensitive matching
always chain `t:lowercase` first, and the byte-level input is then
already ASCII-lowercased. As long as you don't write custom rules
that skip `t:lowercase`, you're covered. If you have a rule that
specifically needs Unicode-aware case folding, apply
`t:normalisePath` or a custom transformation upstream.

### UTF-8 encoding of request body

Coraza reads request bodies as bytes. Transformation pipelines that
decode to strings (`t:utf8toUnicode`) use UTF-8 with a
replacement-character fallback on invalid sequences.

**Implication:** a payload with malformed UTF-8 could render
differently after `t:utf8toUnicode` than to a downstream handler that
uses stricter decoding. This is a theoretical gap — no known exploit
in the wild — but it does exist.

**Mitigation:** reject malformed UTF-8 at an earlier layer (reverse
proxy, WAF-ahead-of-Coraza, or an application-level middleware that
runs before pycoraza). Starlette and FastAPI already reject
non-UTF-8 query strings at the framework level when a route declares
a `str`-typed parameter.

### Oversize request fields

libcoraza has internal buffers for method, URL, protocol, and remote
address. Oversize fields are clipped, not rejected. This is
deliberate — rejection would turn into an uncaught exception, and an
uncaught exception would let the framework's own `except` handler
bypass the WAF.

**Implication:** a 10MB method name is truncated to the first N bytes
and Coraza only evaluates the prefix.

**Mitigation:** WSGI and ASGI servers (gunicorn, uvicorn) already
reject oversize request lines well before pycoraza is invoked. The
clipping is defense-in-depth.

### Shared WAF across threads and event loops

One `WAF` instance can be shared across threads (Flask + gunicorn
workers, Starlette + uvicorn workers). libcoraza synchronizes
internally. Do NOT share a single `Transaction` — those are
per-request.

The ASGI adapter runs blocking Coraza calls via
`asyncio.to_thread`, so a slow rule evaluation does not stall the
event loop.

## Audit checklist for new changes

Before merging any change that touches request flow:

1. **Measure block rate, not just RPS.** Use `bench/k6_run.py` — it
   tracks `blocked_attacks` and `missed_attacks` separately. Both
   numbers must stay the same or improve.
2. **Check adapter except paths.** If new code can `raise`, trace what
   the surrounding `except` does. Does it log and continue? That's a
   bypass.
3. **Check default values.** Any new option must default to the
   stricter choice. Fast-paths that skip evaluation must be opt-in.
4. **Re-run `pytest tests/signals tests/callbacks`.** These are the
   Go-runtime landmine suites.
5. **Load-test with a real attack mix.** The k6 scenarios in
   `bench/k6/` include SQLi, XSS, and oversize payloads.

See [`./security-checklist.md`](./security-checklist.md) for the
commit-level security-impact checklist.
