"""WAFPool: one WAF reference shared across threads in a process.

Rationale: libcoraza's Go runtime handles scheduling, so a single WAF
is thread-safe. The `Pool` abstraction exists for API parity with
coraza-node, letting callers `new_transaction()` without caring how
many WAFs back the pool — useful for single-process, multi-thread
deployments like FastAPI + uvicorn workers.

For multi-process scaling, have each worker create its own WAF.
Sharing a WAF handle across forked processes is NOT supported: Go's
runtime state does not survive `fork()`.
"""

from __future__ import annotations

from .transaction import Transaction
from .types import ProcessMode, WAFConfig
from .waf import WAF, create_waf


class WAFPool:
    """A shared WAF handle with per-transaction construction.

    Matches the shape of `coraza-node`'s `WAFPool` — `new_transaction()`
    hands back a Transaction without the caller caring which worker
    executes it.
    """

    __slots__ = ("_size", "_waf")

    def __init__(self, config: WAFConfig, *, size: int = 1) -> None:
        if size < 1:
            raise ValueError("WAFPool size must be >= 1")
        self._waf = create_waf(config)
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    @property
    def mode(self) -> ProcessMode:
        return self._waf.mode

    @property
    def waf(self) -> WAF:
        return self._waf

    def new_transaction(self, tx_id: str | None = None) -> Transaction:
        return self._waf.new_transaction(tx_id)

    def close(self) -> None:
        self._waf.close()

    def __enter__(self) -> WAFPool:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def create_waf_pool(config: WAFConfig, *, size: int = 1) -> WAFPool:
    return WAFPool(config, size=size)


__all__ = ["WAFPool", "create_waf_pool"]
