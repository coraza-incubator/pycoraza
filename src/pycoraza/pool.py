"""WAFRef: a thin reference wrapper around a single WAF.

`WAFRef` adapts a single `WAF` to the same `new_transaction()` shape
adapters expect; it is **NOT** a multi-process pool — see
`docs/scaling.md` for gunicorn / uvicorn worker patterns.

Frameworks (Flask, Starlette, FastAPI, Django) call
`waf.new_transaction()` against an opaque "WAF-like" handle. Some
consumers prefer to construct a WAF reference at module level via a
single config-shaped factory; `WAFRef` is that factory's output. For
multi-process scaling, have each worker create its own WAF — Go's
runtime state does not survive `fork()`.
"""

from __future__ import annotations

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

    __slots__ = ("_waf",)

    def __init__(self, config: WAFConfig) -> None:
        self._waf = create_waf(config)

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


def create_waf_ref(config: WAFConfig) -> WAFRef:
    return WAFRef(config)


__all__ = ["WAFRef", "create_waf_ref"]
