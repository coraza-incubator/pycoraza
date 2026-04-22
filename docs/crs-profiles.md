# CRS profiles

How to pick and tune a CRS rule-set preset.

pycoraza ships with four profile helpers that emit SecLang rules:
`recommended()`, `balanced()`, `strict()`, and `permissive()`. This
page explains what each one is for, the full `CrsOptions` surface,
and how to layer in your own SecLang.

## What is CRS?

The OWASP [Core Rule Set](https://coreruleset.org/) is the de-facto
open-source WAF rule collection. It's a set of SecLang rules
covering SQL injection, XSS, path traversal, RCE, protocol
violations, scanners, data leaks, and more. pycoraza bundles a
pinned CRS release under `src/pycoraza/coreruleset/rules/` and
generates `Include` directives that libcoraza reads at WAF
construction time.

CRS is paranoia-tiered: higher paranoia means more rules, more
potential false positives, more coverage. Most deployments start at
paranoia 1, promote to 2 after tuning, and rarely reach 3 or 4
outside hardened environments.

## The profiles

All four profiles return a SecLang rules string. Pass it to
`WAFConfig(rules=...)`.

### `recommended(paranoia=1)`

Balanced defaults suitable for most deployments.

- `paranoia=1` (permissive tier).
- Inbound anomaly threshold: `5`. Outbound: `4`.
- `anomaly_block=True` — block when a request crosses the threshold.
- Excludes PHP, Java, and .NET language-specific rule files — they
  add false-positive surface for Python stacks. Override via
  `exclude=()` or `exclude=("php",)`.

Use when: you don't know which profile you want. This is the right
starting point.

```python
from pycoraza.coreruleset import recommended
rules = recommended(paranoia=1)
```

### `balanced(**overrides)`

`recommended` with `paranoia=2` and unchanged thresholds.

Use when: you've run `recommended` in detect mode for a while, tuned
away the false positives you care about, and want more coverage.
Paranoia 2 pulls in a second tier of CRS rules that catch more
evasions at the cost of more false positives.

```python
from pycoraza.coreruleset import balanced
rules = balanced()  # paranoia=2
```

### `strict(**overrides)`

Paranoia 3 with tight thresholds (`inbound=3`, `outbound=3`).

Use when: you're guarding a high-value target and willing to trade
availability for coverage. Expect false positives; build an
exceptions mechanism before flipping this on.

```python
from pycoraza.coreruleset import strict
rules = strict()
```

### `permissive(**overrides)`

Paranoia 1 with loose thresholds (`inbound=10`, `outbound=8`) and
`anomaly_block=False`.

Use when: you want rule matches logged but don't want blocks until
you've tuned. Pairs well with `mode=ProcessMode.DETECT`.

```python
from pycoraza.coreruleset import permissive
rules = permissive()
```

## CrsOptions

All four profile functions accept the same tuning knobs under the
hood. If you need finer control, build a `CrsOptions` directly or
pass keyword overrides.

```python
from pycoraza.coreruleset import CrsOptions, recommended

rules = recommended(
    paranoia=2,
    exclude=("php", "java", "dotnet"),
    outbound_exclude=("php", "java", "dotnet"),
    inbound_anomaly_threshold=7,
    outbound_anomaly_threshold=5,
    anomaly_block=True,
    exclude_categories=(),
    extra="",
)
```

### `paranoia`: `1 | 2 | 3 | 4`

CRS paranoia tier. Higher = more rules loaded.

- `1` — default, permissive; baseline coverage.
- `2` — stricter; pulls in evasion-catching rules.
- `3` — very strict; expect false positives.
- `4` — paranoid; almost certainly too strict for public web apps.

### `exclude`: tuple of `LanguageTag`

Skip language-specific rule files for inbound phases. Filenames
matching `REQUEST-*-<tag>-*.conf` or ending in `-<tag>.conf` are
omitted. Valid tags: `"php"`, `"java"`, `"dotnet"`, `"nodejs"`,
`"iis"`, `"generic"`.

Default: `("php", "java", "dotnet")` — skip non-Python language
families. If you're fronting a PHP app behind a Python proxy, include
`"php"` in the loaded set by passing `exclude=()` or a narrower
tuple.

### `outbound_exclude`: tuple of `LanguageTag`

Same as `exclude`, but for `RESPONSE-*` files. Default matches
`exclude`.

### `inbound_anomaly_threshold`: int

CRS accumulates an anomaly score per request across phase 1+2. When
the score crosses this threshold, rule `949110` fires and blocks.

- Lower = block sooner (more false positives).
- Higher = more attacks slip past (fewer false positives).

Default `5` is the CRS-recommended starting point.

### `outbound_anomaly_threshold`: int

Same as inbound, but for phase 3+4 and the `959100` rule. Default `4`.

Only matters if you run with `inspect_response=True`.

### `anomaly_block`: bool

When `True` (default), a request crossing the threshold is blocked.
When `False`, CRS still scores the request and logs rule matches,
but does not trigger the blocking rule. Useful for running in
parallel with a primary WAF.

### `exclude_categories`: tuple of `CrsCategory`

Skip entire CRS rule categories. Categories are three-digit
prefixes: `"941"` for XSS, `"942"` for SQLi, `"930"` for LFI,
`"932"` for RCE, and so on. See the CRS documentation for the full
list.

Example: disable the application-scanner-detection category because
it has too many false positives on a legitimate monitoring service:

```python
rules = recommended(exclude_categories=("913",))
```

### `extra`: str

Arbitrary SecLang directives appended after the CRS includes. Use
this to add custom rules, tweak existing rules, or override actions.

Example: a custom rule that blocks a specific user-agent string:

```python
rules = recommended(extra="""
SecRule REQUEST_HEADERS:User-Agent "@contains badbot" \\
    "id:1000001,phase:1,deny,status:403,msg:'blocked user-agent'"
""")
```

Because `extra` is appended AFTER the CRS includes, it can override
earlier `SecAction` settings like `tx.blocking_paranoia_level` or
`tx.inbound_anomaly_score_threshold`. Use this as an escape hatch,
not as a primary configuration surface.

## Writing custom SecLang

A `CrsOptions.extra` string can contain anything libcoraza's SecLang
parser accepts. Useful patterns:

**Rule exclusion by id** (a classic false-positive remedy):

```python
extra = "SecRuleRemoveById 942100"
```

**Rule exclusion scoped to a path:**

```python
extra = """
SecRule REQUEST_URI "@beginsWith /admin/upload" \\
    "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
"""
```

**Custom allowlist for a parameter:**

```python
extra = """
SecRule REQUEST_URI "@beginsWith /search" \\
    "id:1000002,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:q"
"""
```

**Raise your own anomaly score bump** for a custom suspicious
signal:

```python
extra = """
SecRule REQUEST_HEADERS:X-Forwarded-For "@contains 127.0.0.1" \\
    "id:1000003,phase:1,pass,nolog,t:none,\\
     setvar:tx.anomaly_score_pl1=+3"
"""
```

Keep custom rule ids above `1000000` — CRS reserves everything
below for its own rules.

## Where rules come from on disk

`src/pycoraza/coreruleset/rules/` contains the CRS `.conf` files.
`_rules_dir()` resolves that path via `importlib.resources` so it
works from a wheel and from an editable install.

The pinned CRS tag is read from `native/version.txt` and fetched at
build time by `native/scripts/build-libcoraza.sh`. To bump the CRS
version: update `native/version.txt`, rebuild libcoraza, rerun the
FTW corpus.

## See also

- [OWASP CRS upstream](https://coreruleset.org/) — the authoritative
  documentation for individual rules.
- [`./quickstart.md`](./quickstart.md) — first block with
  `recommended()`.
- [`./threat-model.md`](./threat-model.md) — trust model for rule
  sets.
- [`./performance.md`](./performance.md) — how paranoia and
  threshold choices affect throughput.
