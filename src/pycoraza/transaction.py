"""Per-request Transaction. Parallel to `@coraza/core` Transaction."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from .abi import CorazaError
from .types import Interruption, MatchedRule, RequestInfo, ResponseInfo

if TYPE_CHECKING:
    from .waf import WAF


class Transaction:
    """A per-request evaluation context.

    Lifecycle mirrors coraza-node's `Transaction`:
        1. process_connection
        2. add_request_headers + process_uri + process_request_headers
           (or fused via process_request_bundle)
        3. append_request_body + process_request_body
        4. process_response_headers + append_response_body + process_response_body
        5. process_logging
        6. close
    """

    __slots__ = (
        "_cached_interruption",
        "_closed",
        "_lock",
        "_matched_rules",
        "_matches_lock",
        "_request_body_started",
        "_response_body_started",
        "_tx",
        "_waf",
    )

    def __init__(self, waf: WAF, tx_handle: object) -> None:
        self._waf = waf
        self._tx = tx_handle
        self._lock = threading.Lock()
        self._closed = False
        self._request_body_started = False
        self._response_body_started = False
        self._cached_interruption: Interruption | None = None
        # The error callback fires from the calling Python thread (cgo
        # invokes callbacks on the same OS thread that entered Go), but
        # we still guard the list — defensive against misuse from
        # adapter code that interleaves phases across threads on the
        # same Transaction (unsupported but easy to mis-write).
        self._matches_lock = threading.Lock()
        self._matched_rules: list[MatchedRule] = []

    def _record_matched_rule(self, rule: MatchedRule) -> None:
        """Append a match recorded by the WAF-level error callback.

        Called by `WAF` while a phase function is running on this
        thread. Public-ish so the WAF callback can reach it without
        breaking encapsulation through getters.
        """
        with self._matches_lock:
            self._matched_rules.append(rule)

    def matched_rules(self) -> list[MatchedRule]:
        """Snapshot of every rule that fired during this transaction.

        Returns a fresh list; callers may freely mutate it. Order is
        the order rules fired (chronological), so the LAST entry is
        typically the disruptive rule on a CRS anomaly-score block.
        """
        with self._matches_lock:
            return list(self._matched_rules)

    @contextmanager
    def _active(self) -> Iterator[None]:
        """Mark this transaction as the WAF's active one for the call.

        cgo invokes the error callback on the OS thread that entered
        Go, so the per-thread `WAF._active` slot is the correct routing
        key. We set it on enter and clear it on exit, including on the
        error path — leaving stale state would silently pin matches to
        a completed transaction.
        """
        prior = getattr(self._waf._active, "tx", None)
        self._waf._set_active_transaction(self)
        try:
            yield
        finally:
            self._waf._set_active_transaction(prior)

    def _check_interruption(self) -> bool:
        """Poll libcoraza for a pending interruption.

        libcoraza's phase functions return 0 even when the transaction
        has been disrupted — the Go engine's disruption signal is
        exposed via `coraza_intervention()`. Cache the first one we
        see so `interruption()` returns consistently.
        """
        if self._cached_interruption is not None:
            return True
        intr = self._waf.abi.intervention(self.handle)
        if intr is None:
            return False
        self._cached_interruption = self._enrich_interruption(intr)
        return True

    def _enrich_interruption(self, intr: Interruption) -> Interruption:
        """Patch the rule id on an interruption with the last match.

        The C `coraza_intervention_t` struct does not carry the rule id
        of the matched rule, so libcoraza always returns rule_id=0. The
        contributing rule arrived via the error callback; the LAST
        match before disruption is, by Coraza's evaluation order, the
        disruptive rule (or — for CRS anomaly-score blocks — the
        949110/980130 finalizer that crossed the score threshold).
        Operators read this field for triage; callers needing the full
        chain use `matched_rules()`.
        """
        if intr.rule_id != 0:
            return intr
        with self._matches_lock:
            last = self._matched_rules[-1] if self._matched_rules else None
        if last is None:
            return intr
        return Interruption(
            rule_id=last.id,
            action=intr.action,
            status=intr.status,
            data=intr.data or last.message,
            source=intr.source,
        )

    @property
    def waf(self) -> WAF:
        return self._waf

    @property
    def handle(self) -> object:
        if self._closed:
            raise CorazaError("Transaction: used after close")
        return self._tx

    def process_connection(
        self,
        client_ip: str,
        client_port: int = 0,
        server_ip: str = "",
        server_port: int = 0,
    ) -> None:
        with self._active():
            self._waf.abi.process_connection(
                self.handle, client_ip, client_port, server_ip, server_port
            )

    def process_uri(self, uri: str, method: str, protocol: str = "HTTP/1.1") -> None:
        with self._active():
            self._waf.abi.process_uri(self.handle, uri, method, protocol)

    def add_request_header(self, name: str, value: str) -> None:
        self._waf.abi.add_request_header(self.handle, name, value)

    def add_request_headers(self, headers: Iterable[tuple[str, str]]) -> None:
        self._waf.abi.add_request_headers(self.handle, headers)

    def process_request_headers(self) -> bool:
        if self._cached_interruption is not None:
            return True
        with self._active():
            self._waf.abi.process_request_headers(self.handle)
            return self._check_interruption()

    def append_request_body(self, chunk: bytes) -> None:
        if chunk:
            self._waf.abi.append_request_body(self.handle, chunk)
            self._request_body_started = True

    def process_request_body(self) -> bool:
        if self._cached_interruption is not None:
            return True
        with self._active():
            self._waf.abi.process_request_body(self.handle)
            return self._check_interruption()

    def process_request_bundle(
        self, request: RequestInfo, body: bytes | None = None
    ) -> bool:
        """Drive phase 1 + phase 2 in a single call.

        Returns True if the WAF interrupted the request. Callers should
        call `interruption()` for the full reason.
        """
        self.process_connection(
            request.remote_addr or "",
            request.remote_port or 0,
            "",
            request.server_port or 0,
        )
        self.add_request_headers(request.headers)
        self.process_uri(request.url, request.method, request.protocol)
        if self.process_request_headers():
            return True
        if body:
            self.append_request_body(body)
        return self.process_request_body()

    def process_response_headers(self, status: int, protocol: str = "HTTP/1.1") -> bool:
        if self._cached_interruption is not None:
            return True
        with self._active():
            self._waf.abi.process_response_headers(self.handle, status, protocol)
            return self._check_interruption()

    def add_response_header(self, name: str, value: str) -> None:
        self._waf.abi.add_response_header(self.handle, name, value)

    def add_response_headers(self, headers: Iterable[tuple[str, str]]) -> None:
        self._waf.abi.add_response_headers(self.handle, headers)

    def append_response_body(self, chunk: bytes) -> None:
        if chunk:
            self._waf.abi.append_response_body(self.handle, chunk)
            self._response_body_started = True

    def process_response_body(self) -> bool:
        if self._cached_interruption is not None:
            return True
        with self._active():
            self._waf.abi.process_response_body(self.handle)
            return self._check_interruption()

    def process_response(self, response: ResponseInfo, body: bytes | None = None) -> bool:
        self.add_response_headers(response.headers)
        if self.process_response_headers(response.status, response.protocol):
            return True
        if body and self.is_response_body_processable():
            self.append_response_body(body)
            if self.process_response_body():
                return True
        return False

    def update_status_code(self, status: int) -> None:
        self._waf.abi.update_status_code(self.handle, status)

    def is_response_body_processable(self) -> bool:
        return self._waf.abi.is_response_body_processable(self.handle)

    def is_rule_engine_off(self) -> bool:
        """Cheap predicate adapters use to short-circuit `SecRuleEngine Off`.

        When the WAF is configured with `SecRuleEngine Off` (or
        `DetectionOnly` when callers want to skip even the audit), every
        per-phase round-trip into Go is wasted work — adapters can
        return the downstream response directly after closing the
        transaction.

        Until upstream libcoraza ships `coraza_is_rule_engine_off` this
        raises `NotImplementedError`. Callers MUST treat the raise as
        "assume the engine is on" and continue with the full pipeline:
        a missing predicate is never a bypass.
        """
        return self._waf.abi.is_rule_engine_off(self.handle)

    def is_request_body_accessible(self) -> bool:
        """Predicate: should the request body be fed to the engine?

        Mirrors `is_response_body_processable` for the request side and
        reflects `SecRequestBodyAccess`. Until upstream ships
        `coraza_is_request_body_accessible` this raises
        `NotImplementedError`; adapters MUST continue calling
        `append_request_body` unconditionally rather than skipping on
        the raise.
        """
        return self._waf.abi.is_request_body_accessible(self.handle)

    def is_response_body_accessible(self) -> bool:
        """Predicate: is response-body inspection enabled at all?

        Distinct from `is_response_body_processable`, which answers a
        per-content-type question. `accessible` reflects the global
        `SecResponseBodyAccess` toggle. Raises `NotImplementedError`
        until upstream lands the predicate.
        """
        return self._waf.abi.is_response_body_accessible(self.handle)

    def reset(self) -> None:
        """Reset transaction state for keep-alive connection reuse.

        Coraza's Go engine does not currently support resetting a
        transaction in place — internal phase state, the matched-rule
        log, and pending interventions are bound to the live handle.
        Adapters that want to reuse a transaction across requests on a
        single keep-alive connection MUST close this transaction and
        call `WAF.new_transaction()` for the next one.

        Raises `NotImplementedError` unconditionally on every libcoraza
        version pycoraza currently supports. Track upstream:
        https://github.com/corazawaf/libcoraza/issues — add a
        `coraza_reset_transaction(coraza_transaction_t)` API.
        """
        self._waf.abi.reset_transaction(self.handle)

    def process_logging(self) -> None:
        if self._closed:
            return
        with self._active():
            self._waf.abi.process_logging(self.handle)

    def interruption(self) -> Interruption | None:
        if self._cached_interruption is not None:
            return self._cached_interruption
        intr = self._waf.abi.intervention(self.handle)
        if intr is not None:
            self._cached_interruption = self._enrich_interruption(intr)
        return self._cached_interruption

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._waf.abi.free_transaction(self._tx)
            finally:
                self._closed = True

    def __enter__(self) -> Transaction:
        return self

    def __exit__(self, *_exc: object) -> None:
        try:
            self.process_logging()
        finally:
            self.close()


__all__ = ["Transaction"]
