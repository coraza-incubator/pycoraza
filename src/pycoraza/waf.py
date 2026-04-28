"""WAF: a configured Coraza instance. Parallel to `@coraza/core` WAF."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .abi import Abi, CorazaError, parse_rule_id
from .logger import Logger, silent_logger
from .types import MatchedRule, ProcessMode, WAFConfig

if TYPE_CHECKING:
    from .transaction import Transaction


class WAF:
    """A Coraza WAF. Create via `create_waf(config)`, not by hand."""

    __slots__ = (
        "_abi",
        "_active",
        "_closed",
        "_lock",
        "_logger",
        "_mode",
        "_waf",
    )

    def __init__(self, abi: Abi, waf_handle: object, mode: ProcessMode, logger: Logger) -> None:
        self._abi = abi
        self._waf = waf_handle
        self._mode = mode
        self._logger = logger
        self._lock = threading.Lock()
        self._closed = False
        # Thread-local pointer to the Transaction currently being
        # processed in this Python thread. cgo guarantees error
        # callbacks fire on the OS thread that entered the C->Go call,
        # so this is the right shape: zero contention, no global lock.
        self._active = threading.local()

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

    def new_transaction(self, tx_id: str | None = None) -> Transaction:
        from .transaction import Transaction

        tx_handle = self._abi.new_transaction(self.handle, tx_id)
        return Transaction(self, tx_handle)

    def _set_active_transaction(self, tx: Transaction | None) -> None:
        """Mark `tx` as the transaction whose phase is currently running.

        Adapters / `Transaction` itself wrap each phase call in a
        `_set_active_transaction(self) ... _set_active_transaction(None)`
        bracket so the WAF-level error callback can route matches.
        """
        self._active.tx = tx

    def _on_matched_rule(self, severity: int, log: str) -> None:
        """WAF-wide error-callback handler.

        Parses the rule id out of the canonical Coraza error log line
        and appends a `MatchedRule` to the active transaction. If no
        transaction is active in this thread (e.g. a rule fires during
        `coraza_new_waf` validation), the match is logged but dropped.
        """
        rule_id = parse_rule_id(log)
        match = MatchedRule(id=rule_id, severity=severity, message=log)
        tx: Transaction | None = getattr(self._active, "tx", None)
        if tx is None:
            self._logger.info(
                "rule matched outside transaction",
                rule_id=rule_id,
                severity=severity,
            )
            return
        tx._record_matched_rule(match)
        self._logger.info(
            "rule matched",
            rule_id=rule_id,
            severity=severity,
            msg=log,
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._abi.free_waf(self._waf)
            finally:
                self._closed = True

    def __enter__(self) -> WAF:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def create_waf(config: WAFConfig) -> WAF:
    """Build a Coraza WAF from a WAFConfig.

    `config.rules` is SecLang — either handwritten or emitted by
    `pycoraza.coreruleset.recommended()` and friends.

    The error callback is wired into the config BEFORE
    `coraza_new_waf` consumes it — libcoraza requires callbacks to be
    registered on the config, not the resulting WAF, and there is no
    way to attach them later. The callback routes matches to the
    Transaction active on the calling thread; see `WAF._on_matched_rule`.
    """
    abi = Abi(logger=config.logger)
    logger = config.logger or silent_logger()
    cfg = abi.new_waf_config()
    waf_obj_holder: list[WAF] = []

    def _matched_rule_cb(severity: int, log: str) -> None:
        # `waf_obj_holder` is populated below before any phase runs;
        # libcoraza never invokes error callbacks during `coraza_new_waf`
        # (it processes rule directives there, not requests), so there
        # is no race against the assignment below.
        if waf_obj_holder:
            waf_obj_holder[0]._on_matched_rule(severity, log)

    try:
        abi.rules_add(cfg, config.rules)
        abi.register_error_callback(cfg, _matched_rule_cb)
        waf_handle = abi.new_waf(cfg)
    finally:
        try:
            abi.free_waf_config(cfg)
        except CorazaError:
            pass
    waf = WAF(abi=abi, waf_handle=waf_handle, mode=config.mode, logger=logger)
    waf_obj_holder.append(waf)
    return waf


__all__ = ["WAF", "create_waf"]
