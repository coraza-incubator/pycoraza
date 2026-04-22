"""Static-asset bypass helper shared by every adapter.

Ported from `packages/core/src/skip.ts` in coraza-node. Kept in a
single module so defaults stay in sync across adapters.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Union

from .types import SkipOptions

SkipPredicate = Callable[[str], bool]
SkipArg = Union[SkipOptions, SkipPredicate, bool, None]


def build_skip_predicate(arg: SkipArg) -> SkipPredicate:
    """Return a fast `str -> bool` predicate matching coraza-node semantics.

    - `None` or `True` → default bypass (images, css, js, fonts, /static, /_next/static).
    - `False`          → never skip (run the WAF on every request).
    - `SkipOptions`    → override both extensions and prefixes.
    - `Callable`       → user-supplied predicate; returns True to skip.
    """

    if arg is False:
        return _never_skip
    if callable(arg) and not isinstance(arg, SkipOptions):
        return arg  # type: ignore[return-value]

    opts = arg if isinstance(arg, SkipOptions) else SkipOptions()
    extensions = tuple(ext.lower() for ext in opts.extensions)
    prefixes = tuple(opts.prefixes)
    extras = set(opts.extra_paths)

    def _predicate(path: str) -> bool:
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


def _never_skip(_: str) -> bool:
    return False


__all__ = ["SkipArg", "SkipPredicate", "build_skip_predicate"]
