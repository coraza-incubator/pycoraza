"""Static-asset and opt-in probe bypass helper shared by every adapter.

Ported from `packages/core/src/skip.ts` in coraza-node and extended for
pycoraza-specific opt-in presets (`PROBE_PATHS`, `PROBE_METHODS`).

A skip predicate takes `(method, path)` and returns True to bypass the
WAF. Keeping the signature method-aware lets callers opt into skipping
HEAD/OPTIONS requests without forcing the adapter to parse it twice.
"""

from __future__ import annotations

from collections.abc import Callable

from .types import SkipOptions

SkipPredicate = Callable[[str, str], bool]
SkipArg = SkipOptions | SkipPredicate | bool | None


def build_skip_predicate(arg: SkipArg) -> SkipPredicate:
    """Return a fast `(method, path) -> bool` predicate.

    - `None` or `True` -> default static-asset bypass (images, css, js,
      fonts, common static prefixes). **Does not** skip probe paths or
      HEAD/OPTIONS by default; opt into those via `SkipOptions`.
    - `False` -> never skip.
    - `SkipOptions` -> honor its `extensions`, `prefixes`, `extra_paths`,
      and `methods` fields.
    - `Callable` -> user-supplied predicate. Must accept `(method, path)`
      and return `True` to skip the WAF for that request.

    Matching semantics
    ------------------
    - **Path only.** The predicate sees the URL *path* component, never
      the query string. `?foo=.png` does NOT trip the `.png` extension
      match. Adapters strip the query before invoking the predicate.
    - **Extensions are case-insensitive.** Both the configured tuple
      and the path are lowercased before comparison, so `/Logo.PNG`
      and `/logo.png` match identically.
    - **Compound extensions are NOT supported as a single token.** Only
      the LAST `.<ext>` segment of the path is matched. `/x.tar.gz`
      matches the entry `.gz`, NOT a hypothetical `.tar.gz` entry.
      To skip `*.tar.gz` files specifically, list both `.tar` AND
      `.gz` (which the default tuple already does), OR add the exact
      path string to `extra_paths`.
    - **Prefix match is case-insensitive** because the path is lowered
      before the prefix loop runs. Configure prefixes in lowercase.
    - **Method match is exact, case-insensitive.** The configured
      `methods` set is upper-cased once; the runtime path uppercases
      the incoming method on each call.
    - **`extra_paths` is exact-string match.** No prefix or glob.
      `/healthz` does not match `/healthz/sub`.
    - **Custom callables.** Signature is `(method: str, path: str) -> bool`.
      Return `True` to skip Coraza for this request, `False` to evaluate
      it. The adapter passes the lowercased method and the URL path
      verbatim — your predicate is responsible for any normalization
      it cares about.

    Security note
    -------------
    Skip predicates are a **performance optimization, not a security
    boundary.** A predicate that returns `True` for `/api/...` paths
    silently disables the WAF for the entire API surface, which is
    almost never what an operator wants. The fail-closed posture
    documented in `docs/threat-model.md` (`on_waf_error="block"`,
    `mode=BLOCK`) only protects against WAF *errors*; it does not
    second-guess a user-configured bypass.

    Audit your skip configuration against your routing table before
    each release. A new dynamic route under `/static/` will be
    silently bypassed by the default predicate, and the WAF cannot
    warn you about something it never saw.
    """

    if arg is False:
        return _never_skip
    if callable(arg) and not isinstance(arg, SkipOptions):
        return arg  # type: ignore[return-value]

    opts = arg if isinstance(arg, SkipOptions) else SkipOptions()
    extensions = tuple(ext.lower() for ext in opts.extensions)
    prefixes = tuple(opts.prefixes)
    extras = set(opts.extra_paths)
    methods = frozenset(m.upper() for m in opts.methods)

    def _predicate(method: str, path: str) -> bool:
        if methods and method.upper() in methods:
            return True
        if not path:
            return False
        lowered = path.lower()
        for pref in prefixes:
            if lowered.startswith(pref):
                return True
        for ext in extensions:
            if lowered.endswith(ext):
                return True
        if path in extras:
            return True
        return False

    return _predicate


def _never_skip(_method: str, _path: str) -> bool:
    return False


__all__ = ["SkipArg", "SkipPredicate", "build_skip_predicate"]
