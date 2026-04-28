"""Pythonic wrapper over the libcoraza C ABI.

Every other module in pycoraza goes through `Abi` to reach libcoraza.
This keeps lifetime management, GIL handling, and error translation in
one place.

Lifetime contract:
  * `new_waf_config` / `free_waf_config` — config is consumed by
    `new_waf` and freed after. Never double-free.
  * `new_waf` → retained by `WAF`; freed on close.
  * `new_transaction` → retained by `Transaction`; freed on close.
  * Interventions returned by `intervention()` are owned by libcoraza;
    call `free_intervention` once and only once per returned pointer.
  * `matched_rule_t` handles passed to the error callback are owned by
    libcoraza for the duration of the callback; copy anything out
    before returning.

GIL contract:
  * Every cffi `@ffi.callback` is registered via `register_callback`,
    which wraps the Python function in a `PyGILState_Ensure` /
    `PyGILState_Release` trampoline so Go can invoke it from any
    goroutine OS thread.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, Protocol

from .types import Interruption

if TYPE_CHECKING:
    from cffi.api import FFI

    from .logger import Logger


_INIT_LOCK = threading.Lock()
_INITIALIZED = False
_BINDINGS: _BindingsLike | None = None


class _BindingsLike(Protocol):
    ffi: FFI
    lib: Any


def _bindings() -> _BindingsLike:
    """Load `pycoraza._bindings` lazily and exactly once per process.

    Go's runtime cannot be initialized twice. We enforce this via a
    module-level singleton; `importlib.reload` is unsupported.
    """
    global _INITIALIZED, _BINDINGS
    if _INITIALIZED and _BINDINGS is not None:
        return _BINDINGS
    with _INIT_LOCK:
        if _INITIALIZED and _BINDINGS is not None:
            return _BINDINGS
        from . import _bindings as b
        _BINDINGS = b  # type: ignore[assignment]
        _INITIALIZED = True
        return _BINDINGS


class CorazaError(RuntimeError):
    """Raised for any libcoraza-level failure."""


class Abi:
    """Thin wrapper over the cffi-generated `lib`.

    One instance per process is enough — the underlying Go runtime is
    a singleton. `WAF` owns one reference and threads through.
    """

    def __init__(self, logger: Logger | None = None) -> None:
        b = _bindings()
        self._ffi = b.ffi
        self._lib = b.lib
        self._logger = logger
        self._callback_refs: list[object] = []

    @property
    def ffi(self) -> FFI:
        return self._ffi

    @property
    def lib(self) -> Any:
        return self._lib

    def _check(self, rc: int, op: str) -> int:
        if rc < 0:
            raise CorazaError(f"libcoraza {op} failed: rc={rc}")
        return rc

    def new_waf_config(self) -> Any:
        cfg = self._lib.coraza_new_waf_config()
        if not cfg:
            raise CorazaError("libcoraza: coraza_new_waf_config returned null")
        return cfg

    def rules_add(self, cfg: Any, rules: str) -> None:
        self._check(self._lib.coraza_rules_add(cfg, _utf8(rules)), "coraza_rules_add")

    def rules_add_file(self, cfg: Any, path: str) -> None:
        self._check(
            self._lib.coraza_rules_add_file(cfg, _utf8(path)),
            "coraza_rules_add_file",
        )

    def free_waf_config(self, cfg: Any) -> None:
        self._check(self._lib.coraza_free_waf_config(cfg), "coraza_free_waf_config")

    def new_waf(self, cfg: Any) -> Any:
        err_ptr = self._ffi.new("char **")
        waf = self._lib.coraza_new_waf(cfg, err_ptr)
        if not waf:
            detail = _from_c(self._ffi, err_ptr[0]) or "unknown error"
            raise CorazaError(f"libcoraza: coraza_new_waf failed: {detail}")
        return waf

    def rules_count(self, waf: Any) -> int:
        return int(self._lib.coraza_rules_count(waf))

    def rules_merge(self, dst: Any, src: Any) -> None:
        err_ptr = self._ffi.new("char **")
        rc = self._lib.coraza_rules_merge(dst, src, err_ptr)
        if rc != 0:
            detail = _from_c(self._ffi, err_ptr[0]) or f"rc={rc}"
            raise CorazaError(f"libcoraza: coraza_rules_merge failed: {detail}")

    def free_waf(self, waf: Any) -> None:
        self._check(self._lib.coraza_free_waf(waf), "coraza_free_waf")

    def new_transaction(self, waf: Any, tx_id: str | None = None) -> Any:
        if tx_id is None:
            tx = self._lib.coraza_new_transaction(waf)
        else:
            tx = self._lib.coraza_new_transaction_with_id(waf, _utf8(tx_id))
        if not tx:
            raise CorazaError("libcoraza: coraza_new_transaction returned null")
        return tx

    def free_transaction(self, tx: Any) -> None:
        self._check(self._lib.coraza_free_transaction(tx), "coraza_free_transaction")

    def process_connection(
        self,
        tx: Any,
        client_ip: str,
        client_port: int,
        server_ip: str = "",
        server_port: int = 0,
    ) -> None:
        self._check(
            self._lib.coraza_process_connection(
                tx, _utf8(client_ip), client_port, _utf8(server_ip), server_port
            ),
            "coraza_process_connection",
        )

    def process_uri(self, tx: Any, uri: str, method: str, protocol: str) -> None:
        self._check(
            self._lib.coraza_process_uri(tx, _utf8(uri), _utf8(method), _utf8(protocol)),
            "coraza_process_uri",
        )

    def add_request_header(self, tx: Any, name: str, value: str) -> None:
        name_bytes = name.encode("utf-8", errors="replace")
        value_bytes = value.encode("utf-8", errors="replace")
        self._check(
            self._lib.coraza_add_request_header(
                tx, name_bytes, len(name_bytes), value_bytes, len(value_bytes)
            ),
            "coraza_add_request_header",
        )

    def add_request_headers(self, tx: Any, headers: Iterable[tuple[str, str]]) -> None:
        for name, value in headers:
            self.add_request_header(tx, name, value)

    def process_request_headers(self, tx: Any) -> int:
        return self._check(
            self._lib.coraza_process_request_headers(tx), "coraza_process_request_headers"
        )

    def append_request_body(self, tx: Any, chunk: bytes) -> None:
        self._check(
            self._lib.coraza_append_request_body(tx, chunk, len(chunk)),
            "coraza_append_request_body",
        )

    def process_request_body(self, tx: Any) -> int:
        return self._check(
            self._lib.coraza_process_request_body(tx), "coraza_process_request_body"
        )

    def request_body_from_file(self, tx: Any, path: str) -> None:
        self._check(
            self._lib.coraza_request_body_from_file(tx, _utf8(path)),
            "coraza_request_body_from_file",
        )

    def add_get_args(self, tx: Any, name: str, value: str) -> None:
        self._check(
            self._lib.coraza_add_get_args(tx, _utf8(name), _utf8(value)),
            "coraza_add_get_args",
        )

    def update_status_code(self, tx: Any, status: int) -> None:
        self._lib.coraza_update_status_code(tx, status)

    def add_response_header(self, tx: Any, name: str, value: str) -> None:
        name_bytes = name.encode("utf-8", errors="replace")
        value_bytes = value.encode("utf-8", errors="replace")
        self._check(
            self._lib.coraza_add_response_header(
                tx, name_bytes, len(name_bytes), value_bytes, len(value_bytes)
            ),
            "coraza_add_response_header",
        )

    def add_response_headers(self, tx: Any, headers: Iterable[tuple[str, str]]) -> None:
        for name, value in headers:
            self.add_response_header(tx, name, value)

    def process_response_headers(self, tx: Any, status: int, protocol: str) -> int:
        return self._check(
            self._lib.coraza_process_response_headers(tx, status, _utf8(protocol)),
            "coraza_process_response_headers",
        )

    def append_response_body(self, tx: Any, chunk: bytes) -> None:
        self._check(
            self._lib.coraza_append_response_body(tx, chunk, len(chunk)),
            "coraza_append_response_body",
        )

    def process_response_body(self, tx: Any) -> int:
        return self._check(
            self._lib.coraza_process_response_body(tx), "coraza_process_response_body"
        )

    def is_response_body_processable(self, tx: Any) -> bool:
        return bool(self._lib.coraza_is_response_body_processable(tx))

    def is_rule_engine_off(self, tx: Any) -> bool:
        """Cheap predicate: is `SecRuleEngine Off` set on the active config?

        Adapters use this for early-exit after `new_transaction()` so a
        detect/disabled deployment skips the per-phase round-trip. The
        upstream C ABI does NOT yet expose this; track:
        https://github.com/corazawaf/libcoraza/issues/new — add a
        `coraza_is_rule_engine_off(coraza_transaction_t)` predicate.

        Until upstream lands a function, this raises `NotImplementedError`
        rather than silently returning a guess. Callers MUST treat the
        absence as "engine may be on" and continue with the normal
        evaluation pipeline — never bypass on raise.
        """
        fn = getattr(self._lib, "coraza_is_rule_engine_off", None)
        if fn is None:
            raise NotImplementedError(
                "libcoraza does not expose coraza_is_rule_engine_off; "
                "needs upstream API addition. "
                "See https://github.com/corazawaf/libcoraza/issues for tracking."
            )
        return bool(fn(tx))

    def is_request_body_accessible(self, tx: Any) -> bool:
        """Predicate: is the request body in scope for this transaction?

        Mirrors `is_response_body_processable` for the request side.
        Upstream libcoraza does not yet ship `coraza_is_request_body_accessible`;
        until it does we raise `NotImplementedError`. Adapters must
        continue to drive request-body phases unconditionally — fail
        closed, never skip body inspection on a missing predicate.
        """
        fn = getattr(self._lib, "coraza_is_request_body_accessible", None)
        if fn is None:
            raise NotImplementedError(
                "libcoraza does not expose coraza_is_request_body_accessible; "
                "needs upstream API addition. "
                "See https://github.com/corazawaf/libcoraza/issues for tracking."
            )
        return bool(fn(tx))

    def is_response_body_accessible(self, tx: Any) -> bool:
        """Predicate distinct from `is_response_body_processable`.

        `processable` answers "should the engine evaluate this content
        type?" (driven by `SecResponseBodyMimeType`). `accessible`
        answers "is response-body inspection turned on at all?" (driven
        by `SecResponseBodyAccess`). Upstream libcoraza does not yet
        expose this predicate — raises `NotImplementedError`.
        """
        fn = getattr(self._lib, "coraza_is_response_body_accessible", None)
        if fn is None:
            raise NotImplementedError(
                "libcoraza does not expose coraza_is_response_body_accessible; "
                "needs upstream API addition. "
                "See https://github.com/corazawaf/libcoraza/issues for tracking."
            )
        return bool(fn(tx))

    def reset_transaction(self, tx: Any) -> None:
        """Reset transaction state for keep-alive reuse.

        Coraza's Go engine has no public reset on a transaction — its
        internal `Variables` map and matched-rule state are owned by
        the live transaction and are not safe to reuse. Until libcoraza
        exposes `coraza_reset_transaction`, callers MUST close the
        current transaction and call `new_transaction()` for the next
        request.
        """
        fn = getattr(self._lib, "coraza_reset_transaction", None)
        if fn is None:
            raise NotImplementedError(
                "libcoraza does not expose coraza_reset_transaction; "
                "transaction reuse is not supported by the current "
                "libcoraza version — create a new transaction instead. "
                "See https://github.com/corazawaf/libcoraza/issues for tracking."
            )
        self._check(fn(tx), "coraza_reset_transaction")

    def process_logging(self, tx: Any) -> None:
        self._check(self._lib.coraza_process_logging(tx), "coraza_process_logging")

    def intervention(self, tx: Any) -> Interruption | None:
        ptr = self._lib.coraza_intervention(tx)
        if ptr is None or ptr == self._ffi.NULL:
            return None
        try:
            action = _from_c(self._ffi, ptr.action) or ""
            data = _from_c(self._ffi, ptr.data) or ""
            status = int(ptr.status or 0)
            # `coraza_intervention_t` (libcoraza) carries no rule id —
            # WAF.create_waf wires a per-WAF error callback that records
            # matched rules onto the active Transaction. The disruptive
            # rule is the LAST entry recorded, so callers should read
            # `Transaction.matched_rules()[-1]` for the contributing id.
            rule_id = int(getattr(ptr, "rule_id", 0) or 0)
            return Interruption(
                rule_id=rule_id, action=action, status=status, data=data
            )
        finally:
            self._lib.coraza_free_intervention(ptr)

    def register_error_callback(
        self, cfg: Any, callback: ErrorCallback
    ) -> None:
        """Install an error callback.

        The cffi trampoline automatically acquires the GIL, so the
        callable may be arbitrary Python. Go invokes it from goroutine
        OS threads; never assume the calling thread is the one that
        registered the callback.
        """

        @self._ffi.callback("void(void *, coraza_matched_rule_t)")
        def _tramp(_userdata: Any, rule_handle: Any) -> None:
            try:
                raw = self._lib.coraza_matched_rule_get_error_log(rule_handle)
                log = _from_c(self._ffi, raw) or ""
                sev = int(self._lib.coraza_matched_rule_get_severity(rule_handle))
                callback(sev, log)
            except Exception as exc:  # pragma: no cover - defensive
                if self._logger is not None:
                    self._logger.error("pycoraza callback raised", error=repr(exc))

        self._callback_refs.append(_tramp)
        self._check(
            self._lib.coraza_add_error_callback(cfg, _tramp, self._ffi.NULL),
            "coraza_add_error_callback",
        )

    def register_debug_callback(self, cfg: Any, callback: DebugCallback) -> None:
        @self._ffi.callback(
            "void(void *, coraza_debug_log_level_t, const char *, const char *)"
        )
        def _tramp(_userdata: Any, level: int, message: Any, fields: Any) -> None:
            try:
                msg = _from_c(self._ffi, message) or ""
                flds = _from_c(self._ffi, fields) or ""
                callback(int(level), msg, flds)
            except Exception as exc:  # pragma: no cover
                if self._logger is not None:
                    self._logger.error("pycoraza debug callback raised", error=repr(exc))

        self._callback_refs.append(_tramp)
        self._check(
            self._lib.coraza_add_debug_log_callback(cfg, _tramp, self._ffi.NULL),
            "coraza_add_debug_log_callback",
        )


def _utf8(s: str) -> bytes:
    return s.encode("utf-8", errors="replace")


def _from_c(ffi: FFI, ptr: Any) -> str | None:
    if ptr == ffi.NULL or not ptr:
        return None
    raw = ffi.string(ptr)
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


ErrorCallback = Callable[[int, str], None]
DebugCallback = Callable[[int, str, str], None]


_RULE_ID_RE = re.compile(r'\[id\s+"(\d+)"\]')


def parse_rule_id(error_log: str) -> int:
    """Extract the matched rule id from a Coraza/CRS error log line.

    Coraza emits matched-rule logs in the canonical CRS shape:
    `... [id "942100"] [msg "..."] ...`. We pull the first `[id "N"]`
    token; if absent (custom rules without an id directive) we return 0.
    """
    if not error_log:
        return 0
    m = _RULE_ID_RE.search(error_log)
    if m is None:
        return 0
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return 0


__all__ = ["Abi", "CorazaError", "parse_rule_id"]
