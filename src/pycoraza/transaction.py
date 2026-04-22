"""Per-request Transaction. Parallel to `@coraza/core` Transaction."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import TYPE_CHECKING

from .abi import CorazaError
from .types import Interruption, RequestInfo, ResponseInfo

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
        "_waf",
        "_tx",
        "_lock",
        "_closed",
        "_request_body_started",
        "_response_body_started",
        "_cached_interruption",
    )

    def __init__(self, waf: "WAF", tx_handle: object) -> None:
        self._waf = waf
        self._tx = tx_handle
        self._lock = threading.Lock()
        self._closed = False
        self._request_body_started = False
        self._response_body_started = False
        self._cached_interruption: Interruption | None = None

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
        self._cached_interruption = intr
        return True

    @property
    def waf(self) -> "WAF":
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
        self._waf.abi.process_connection(
            self.handle, client_ip, client_port, server_ip, server_port
        )

    def process_uri(self, uri: str, method: str, protocol: str = "HTTP/1.1") -> None:
        self._waf.abi.process_uri(self.handle, uri, method, protocol)

    def add_request_header(self, name: str, value: str) -> None:
        self._waf.abi.add_request_header(self.handle, name, value)

    def add_request_headers(self, headers: Iterable[tuple[str, str]]) -> None:
        self._waf.abi.add_request_headers(self.handle, headers)

    def process_request_headers(self) -> bool:
        self._waf.abi.process_request_headers(self.handle)
        return self._check_interruption()

    def append_request_body(self, chunk: bytes) -> None:
        if chunk:
            self._waf.abi.append_request_body(self.handle, chunk)
            self._request_body_started = True

    def process_request_body(self) -> bool:
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

    def process_logging(self) -> None:
        if self._closed:
            return
        self._waf.abi.process_logging(self.handle)

    def interruption(self) -> Interruption | None:
        if self._cached_interruption is not None:
            return self._cached_interruption
        intr = self._waf.abi.intervention(self.handle)
        if intr is not None:
            self._cached_interruption = intr
        return intr

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._waf.abi.free_transaction(self._tx)
            finally:
                self._closed = True

    def __enter__(self) -> "Transaction":
        return self

    def __exit__(self, *_exc: object) -> None:
        try:
            self.process_logging()
        finally:
            self.close()


__all__ = ["Transaction"]
