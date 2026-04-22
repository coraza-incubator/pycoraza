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

    - `None` or `True` → default static-asset bypass (images, css, js,
      fonts, common static prefixes). **Does not** skip probe paths or
      HEAD/OPTIONS by default; opt into those via `SkipOptions`.
    - `False` → never skip.
    - `SkipOptions` → honor its `extensions`, `prefixes`, `extra_paths`,
      and `methods` fields.
    - `Callable` → user-supplied predicate. Must accept `(method, path)`.
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
