"""WAFRef: a thin reference wrapper around a single WAF.

`WAFRef` adapts a single `WAF` to the same `new_transaction()` shape
adapters expect; it is **NOT** a multi-process pool — see
`docs/scaling.md` for gunicorn / uvicorn worker patterns. The
historical `WAFPool` name promised pooling we never delivered: the
class always wrapped one WAF and ignored `size>1`. The name has been
corrected to match reality. `WAFPool` remains available as a
deprecated alias through the 1.0 release.

Why keep this layer at all? Frameworks (Flask, Starlette, FastAPI,
Django) call `waf.new_transaction()` against an opaque "WAF-like"
handle. Some consumers prefer to construct a WAF reference at module
level via a single config-shaped factory; `WAFRef` is that factory's
output. For multi-process scaling, have each worker create its own
WAF — Go's runtime state does not survive `fork()`.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from .transaction import Transaction
from .types import ProcessMode, WAFConfig
from .waf import WAF, create_waf

if TYPE_CHECKING:
    from .logger import Logger


class WAFRef:
    """Thin reference wrapper that adapts a single `WAF` to the same
    `new_transaction()` shape adapters expect.

    NOT a multi-process pool — see `docs/scaling.md` for gunicorn /
    uvicorn worker patterns. One WAF per worker process; share the
    `WAFRef` across threads inside a single process.
    """

    __slots__ = ("_size", "_waf")

    def __init__(self, config: WAFConfig, *, size: int = 1) -> None:
        if size < 1:
            raise ValueError("WAFRef size must be >= 1")
        self._waf = create_waf(config)
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    @property
    def mode(self) -> ProcessMode:
        return self._waf.mode

    @property
    def logger(self) -> Logger:
        return self._waf.logger

    @property
    def destroyed(self) -> bool:
        return self._waf._closed

    @property
    def waf(self) -> WAF:
        return self._waf

    def new_transaction(self, tx_id: str | None = None) -> Transaction:
        return self._waf.new_transaction(tx_id)

    def close(self) -> None:
        self._waf.close()

    def __enter__(self) -> WAFRef:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class WAFPool(WAFRef):
    """Deprecated alias for `WAFRef`.

    Kept for compatibility with code written against pre-rename
    pycoraza. New code should use `WAFRef` directly, or simply pass a
    `WAF` from `create_waf` — adapters accept both via the `WAFLike`
    type alias. Will be removed in a future release.
    """

    def __init__(self, config: WAFConfig, *, size: int = 1) -> None:
        warnings.warn(
            "WAFPool is a deprecated alias for WAFRef and was never a real "
            "multi-process pool. Use pycoraza.WAFRef or pass a WAF directly. "
            "See docs/scaling.md for multi-worker recipes.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(config, size=size)


def create_waf_ref(config: WAFConfig, *, size: int = 1) -> WAFRef:
    return WAFRef(config, size=size)


def create_waf_pool(config: WAFConfig, *, size: int = 1) -> WAFRef:
    """Deprecated. Use `pycoraza.create_waf` + `docs/scaling.md` for scaling."""
    warnings.warn(
        "create_waf_pool is deprecated and never created a real pool. "
        "Use pycoraza.create_waf for a single WAF, and follow "
        "docs/scaling.md for multi-worker deployments.",
        DeprecationWarning,
        stacklevel=2,
    )
    return WAFRef(config, size=size)


__all__ = ["WAFPool", "WAFRef", "create_waf_pool", "create_waf_ref"]
