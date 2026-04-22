# Security checklist

The five-question security-impact check every commit must pass.

This page is for reviewers and contributors, not end users. End-user
security material lives in [`./threat-model.md`](./threat-model.md).

## When to run this checklist

Every commit. Perf tuning, refactor, new feature, docs, build change,
dependency bump — every one. Answer the five questions below in your
commit message or PR description. If the answer to any is "I don't
know," stop and investigate.

There is no "this is just a docs change" exemption. Docs describe
behavior; mis-describing behavior is itself a security issue.

## The five questions

### 1. What's the security impact?

State it plainly. Examples:

- "No security impact — pure comment / typo fix."
- "No security impact — adds a test case."
- "Narrows an existing exposure: previously the oversize-header path
  could fall through to the app; now it blocks."
- "Adds a new code path attackers can reach: the new `on_block`
  custom handler is user-supplied and runs with framework privileges."
- "May bypass detection under condition X — documented as
  `inspect_response=False` opt-in."

"No impact" is a valid answer when it's true. Saying "unknown" is
not valid. Investigate until you know.

### 2. Does any new code path handle an exception an attacker could force?

Follow every `except:` upward. Ask:

- Does the catch re-raise, log, or continue?
- If continue, is the request still evaluated by the WAF, or does it
  reach the handler unfiltered?
- Can an attacker trigger this exception reliably?

Raising into a framework's `except BaseException` fast path is a
bypass vector. Starlette, FastAPI, and Flask all have `except`
handlers that will happily pass a request through with a default
error response if pycoraza leaks an exception. The adapters exist in
part to catch exceptions from libcoraza before the framework sees
them.

Rule: never `raise` from inside a middleware body path in a way that
a framework can silently recover from. Either block, or log and
continue — but the choice must be explicit.

### 3. Does it change what Coraza sees?

Encoding changes, truncation, filtering, normalization, caching —
any of these can make Coraza evaluate a different input than what
the attacker sent. Examples of changes that qualify:

- A new body-reading path that decodes bytes differently.
- A filter that strips a header before passing it to Coraza.
- A cache that short-circuits transaction creation.
- A truncation that clips a field.

Confirm behavioral equivalence or document the gap. If you truncate,
document the limit and add a test that exercises the boundary. If
you normalize, document what the normalization is and add an FTW
override if CRS disagrees.

### 4. Does it change when rules fire?

Phase ordering matters. Skipping a phase, reordering calls,
batching, short-circuiting — CRS anomaly-score rules (like `949110`)
must reach their evaluation point. Phase 2 always runs, even on
body-less verbs like GET.

If your change can skip a phase or alter call order, add a test that
asserts a phase-2-dependent rule still fires.

### 5. Are the defaults secure?

- New option? The default must be the stricter choice.
- New fast-path? Default off, opt-in via env var or config.
- New bypass? Default-narrow, opt-in to widen.

Users should not have to opt into security. They should have to opt
out of it. Make the secure path the path of least resistance.

## What to include in the commit message

```
<imperative subject line under 72 chars>

<one paragraph on what changed and why>

Security impact:
  1. What: <answer to question 1>
  2. Exception handling: <answer to question 2>
  3. What Coraza sees: <answer to question 3>
  4. When rules fire: <answer to question 4>
  5. Default safety: <answer to question 5>

<links to relevant issues, upstream commits, test cases>
```

Short answers are fine for uncontroversial changes:

```
Security impact:
  1. No impact — docs only.
  2. N/A — no code paths added.
  3. N/A — no engine interaction.
  4. N/A — no rule-evaluation changes.
  5. N/A — no new options.
```

For anything touching `src/pycoraza/abi.py`, `src/pycoraza/transaction.py`,
or any adapter's `__init__.py`, full answers are required.

## How to verify

- `pytest` — unit, integration, framework, callback, and signal
  suites. Coverage gates enforced.
- `pytest tests/callbacks tests/signals` — Go-runtime landmine
  suite. Must pass before any adapter or ABI change ships.
- `python bench/k6_run.py --framework flask` — `missed_attacks` must
  be 0. Any non-zero value is a bypass.
- `bash testing/ftw/run.sh --framework flask --port 5000` — CRS
  regression corpus. 100% pass rate required.

## Reviewer expectations

If you're reviewing a PR:

- Read the security-impact answers. Reject a PR that doesn't have
  them or has hand-wave answers.
- Look for `except:` clauses that `continue` silently. Any new one
  is an automatic request-changes.
- Check the default value of any new option. If it's the less-secure
  choice, request a flip.
- Run the FTW corpus locally if the PR touches adapter request flow
  or the ABI wrapper. CI runs it too, but a local run lets you
  iterate faster.

## See also

- [`./threat-model.md`](./threat-model.md) — threat model, trust
  boundaries, fail-closed defaults.
- [`../AGENTS.md`](../AGENTS.md) — full contributor guide; this
  checklist is a distilled view of the "Mandatory security checks"
  section there.
