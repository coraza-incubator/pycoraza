"""WAF: a configured Coraza instance. Parallel to `@coraza/core` WAF."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .abi import Abi, CorazaError
from .logger import Logger, silent_logger
from .types import ProcessMode, WAFConfig

if TYPE_CHECKING:
    from .transaction import Transaction


class WAF:
    """A Coraza WAF. Create via `create_waf(config)`, not by hand."""

    __slots__ = ("_abi", "_waf", "_mode", "_logger", "_lock", "_closed")

    def __init__(self, abi: Abi, waf_handle: object, mode: ProcessMode, logger: Logger) -> None:
        self._abi = abi
        self._waf = waf_handle
        self._mode = mode
        self._logger = logger
        self._lock = threading.Lock()
        self._closed = False

    @property
    def mode(self) -> ProcessMode:
        return self._mode

    @property
    def logger(self) -> Logger:
        return self._logger

    @property
    def abi(self) -> Abi:
        return self._abi

    @property
    def handle(self) -> object:
        if self._closed:
            raise CorazaError("WAF: used after close")
        return self._waf

    def rules_count(self) -> int:
        return self._abi.rules_count(self.handle)

    def new_transaction(self, tx_id: str | None = None) -> "Transaction":
        from .transaction import Transaction

        tx_handle = self._abi.new_transaction(self.handle, tx_id)
        return Transaction(self, tx_handle)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._abi.free_waf(self._waf)
            finally:
                self._closed = True

    def __enter__(self) -> "WAF":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def create_waf(config: WAFConfig) -> WAF:
    """Build a Coraza WAF from a WAFConfig.

    `config.rules` is SecLang — either handwritten or emitted by
    `pycoraza.coreruleset.recommended()` and friends.
    """
    abi = Abi(logger=config.logger)
    cfg = abi.new_waf_config()
    try:
        abi.rules_add(cfg, config.rules)
        waf_handle = abi.new_waf(cfg)
    finally:
        try:
            abi.free_waf_config(cfg)
        except CorazaError:
            pass
    logger = config.logger or silent_logger()
    return WAF(abi=abi, waf_handle=waf_handle, mode=config.mode, logger=logger)


__all__ = ["WAF", "create_waf"]
