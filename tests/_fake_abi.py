"""Fake libcoraza bindings for unit-level tests.

This module implements every `coraza_*` symbol that `pycoraza.abi`
calls against. It is wired into `sys.modules["pycoraza._bindings"]`
by `tests.conftest` before the real bindings can be imported, so the
tests run without a compiled native extension.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from typing import Any


class _FakeCData:
    """Minimal stand-in for cffi CData; carries optional encoded bytes.

    Supports `ptr[0]` semantics so code using `ffi.new("char **")`
    out-params can read from it without special-casing the fake.
    """

    __slots__ = ("_bytes", "_value")

    def __init__(self, value: bytes = b"") -> None:
        self._bytes = value
        self._value: Any = None

    def __bool__(self) -> bool:
        return True

    def __getitem__(self, index: int) -> Any:
        if index == 0:
            return self._value if self._value is not None else self
        raise IndexError(index)

    def __setitem__(self, index: int, value: Any) -> None:
        if index == 0:
            self._value = value
            return
        raise IndexError(index)


class _FakeFFI:
    NULL = _FakeCData(b"")

    def string(self, ptr: Any) -> bytes:
        if ptr is None:
            return b""
        if ptr is self.NULL:
            return b""
        if isinstance(ptr, (bytes, bytearray)):
            return bytes(ptr)
        return getattr(ptr, "_bytes", b"")

    def callback(self, _sig: str):
        def decorator(fn):
            return fn

        return decorator

    def new(self, spec: str, init: Any = None) -> _FakeCData:
        if isinstance(init, str):
            return _FakeCData(init.encode("utf-8"))
        if isinstance(init, (bytes, bytearray)):
            return _FakeCData(bytes(init))
        return _FakeCData(b"")


@dataclass
class _InterventionSpec:
    """What an injected intervention should look like."""

    action: str = "deny"
    status: int = 403
    data: str = "blocked"
    rule_id: int = 1001
    disruptive: int = 1
    pause: int = 0


@dataclass
class _InterventionPtr:
    action: Any = None
    data: Any = None
    status: int = 0
    rule_id: int = 0
    disruptive: int = 0
    pause: int = 0

    def __bool__(self) -> bool:
        return self.status != 0 or self.rule_id != 0 or bool(
            getattr(self.action, "_bytes", b"")
        )


@dataclass
class _WafState:
    config: Any
    rules: list[str] = field(default_factory=list)


@dataclass
class _TxState:
    waf: Any
    tx_id: str | None = None
    request_body: list[bytes] = field(default_factory=list)
    response_body: list[bytes] = field(default_factory=list)
    request_headers: list[tuple[str, str]] = field(default_factory=list)
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    uri: str = ""
    method: str = ""
    protocol: str = ""
    client_ip: str = ""
    client_port: int = 0
    connection_done: bool = False
    request_headers_processed: bool = False
    request_body_processed: bool = False
    response_headers_processed: bool = False
    response_body_processed: bool = False
    logged: bool = False
    response_status: int = 0
    interruption_spec: _InterventionSpec | None = None
    intervention_served: bool = False


@dataclass
class _ConfigState:
    rules: list[str] = field(default_factory=list)
    error_callback: Any = None
    debug_callback: Any = None


class FakeLib:
    """In-memory stand-in for the libcoraza shared library."""

    def __init__(self) -> None:
        self.configs: dict[int, _ConfigState] = {}
        self.wafs: dict[int, _WafState] = {}
        self.txs: dict[int, _TxState] = {}
        self.call_log: list[tuple] = []

        self.trigger_uri_contains: str | None = None
        self.trigger_request_header_name: str | None = None
        self.trigger_request_body_contains: bytes | None = None
        self.trigger_response_body_contains: bytes | None = None
        self.trigger_response_headers_status: int | None = None
        self.interruption_spec = _InterventionSpec()

        self.raise_on_new_waf: bool = False
        self.raise_on_new_transaction: bool = False
        self.raise_on_process_uri: bool = False
        self.fail_rc_for: set[str] = set()
        self.response_body_processable: bool = True

        self._ffi = _FakeFFI()

    def _log(self, *call: Any) -> None:
        self.call_log.append(tuple(call))

    def _fail_rc(self, op: str) -> int:
        return -1 if op in self.fail_rc_for else 0

    def coraza_new_waf_config(self) -> Any:
        cfg = _FakeCData(b"cfg")
        self.configs[id(cfg)] = _ConfigState()
        self._log("new_waf_config")
        return cfg

    def coraza_rules_add(self, cfg: Any, rules: bytes) -> int:
        if "rules_add" in self.fail_rc_for:
            return -1
        text = rules.decode("utf-8", errors="replace") if isinstance(rules, (bytes, bytearray)) else str(rules)
        self.configs[id(cfg)].rules.append(text)
        self._log("rules_add", len(text))
        return 0

    def coraza_rules_add_file(self, cfg: Any, path: bytes) -> int:
        if "rules_add_file" in self.fail_rc_for:
            return -1
        self.configs[id(cfg)].rules.append(
            "file:" + path.decode("utf-8", errors="replace")
        )
        self._log("rules_add_file", path)
        return 0

    def coraza_free_waf_config(self, cfg: Any) -> int:
        self.configs.pop(id(cfg), None)
        self._log("free_waf_config")
        return self._fail_rc("free_waf_config")

    def coraza_new_waf(self, cfg: Any, err_ptr: Any = None) -> Any:
        if self.raise_on_new_waf:
            self._log("new_waf_null")
            return None
        waf = _FakeCData(b"waf")
        state = self.configs.get(id(cfg), _ConfigState())
        self.wafs[id(waf)] = _WafState(config=cfg, rules=list(state.rules))
        self._log("new_waf")
        return waf

    def coraza_rules_count(self, waf: Any) -> int:
        state = self.wafs.get(id(waf))
        count = len(state.rules) if state else 0
        self._log("rules_count", count)
        return count

    def coraza_rules_merge(self, dst: Any, src: Any, err_ptr: Any = None) -> int:
        dst_state = self.wafs.get(id(dst))
        src_state = self.wafs.get(id(src))
        if dst_state and src_state:
            dst_state.rules.extend(src_state.rules)
        self._log("rules_merge")
        return self._fail_rc("rules_merge")

    def coraza_free_waf(self, waf: Any) -> int:
        self.wafs.pop(id(waf), None)
        self._log("free_waf")
        return self._fail_rc("free_waf")

    def coraza_new_transaction(self, waf: Any) -> Any:
        if self.raise_on_new_transaction:
            self._log("new_transaction_null")
            return None
        tx = _FakeCData(b"tx")
        self.txs[id(tx)] = _TxState(waf=waf)
        self._log("new_transaction")
        return tx

    def coraza_new_transaction_with_id(self, waf: Any, tx_id: bytes) -> Any:
        if self.raise_on_new_transaction:
            self._log("new_transaction_with_id_null")
            return None
        tx = _FakeCData(b"tx")
        ident = tx_id.decode("utf-8", errors="replace") if isinstance(tx_id, (bytes, bytearray)) else str(tx_id)
        self.txs[id(tx)] = _TxState(waf=waf, tx_id=ident)
        self._log("new_transaction_with_id", ident)
        return tx

    def coraza_free_transaction(self, tx: Any) -> int:
        self.txs.pop(id(tx), None)
        self._log("free_transaction")
        return self._fail_rc("free_transaction")

    def coraza_process_connection(
        self,
        tx: Any,
        client_ip: bytes,
        client_port: int,
        server_ip: bytes,
        server_port: int,
    ) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.client_ip = client_ip.decode("utf-8", errors="replace") if isinstance(client_ip, (bytes, bytearray)) else str(client_ip)
            state.client_port = int(client_port)
            state.connection_done = True
        self._log("process_connection", state.client_ip if state else "", int(client_port))
        return self._fail_rc("process_connection")

    def coraza_process_uri(
        self, tx: Any, uri: bytes, method: bytes, protocol: bytes
    ) -> int:
        if self.raise_on_process_uri:
            return -1
        state = self.txs.get(id(tx))
        if state is not None:
            state.uri = uri.decode("utf-8", errors="replace") if isinstance(uri, (bytes, bytearray)) else str(uri)
            state.method = method.decode("utf-8", errors="replace") if isinstance(method, (bytes, bytearray)) else str(method)
            state.protocol = protocol.decode("utf-8", errors="replace") if isinstance(protocol, (bytes, bytearray)) else str(protocol)
            if self.trigger_uri_contains and self.trigger_uri_contains in state.uri:
                state.interruption_spec = self.interruption_spec
        self._log("process_uri", state.uri if state else "", state.method if state else "")
        return self._fail_rc("process_uri")

    def coraza_add_request_header(
        self, tx: Any, name: bytes, name_len: int, value: bytes, value_len: int
    ) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
            vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
            state.request_headers.append((nm, vl))
            if (
                self.trigger_request_header_name
                and nm.lower() == self.trigger_request_header_name.lower()
            ):
                state.interruption_spec = self.interruption_spec
        self._log("add_request_header", nm if state else "")
        return self._fail_rc("add_request_header")

    def coraza_process_request_headers(self, tx: Any) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.request_headers_processed = True
        self._log("process_request_headers")
        if state and state.interruption_spec is not None:
            return 1
        return self._fail_rc("process_request_headers")

    def coraza_append_request_body(self, tx: Any, chunk: bytes, length: int) -> int:
        state = self.txs.get(id(tx))
        data = bytes(chunk[:length]) if length else b""
        if state is not None:
            state.request_body.append(data)
            if (
                self.trigger_request_body_contains
                and self.trigger_request_body_contains in data
            ):
                state.interruption_spec = self.interruption_spec
        self._log("append_request_body", length)
        return self._fail_rc("append_request_body")

    def coraza_process_request_body(self, tx: Any) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.request_body_processed = True
        self._log("process_request_body")
        if state and state.interruption_spec is not None:
            return 1
        return self._fail_rc("process_request_body")

    def coraza_request_body_from_file(self, tx: Any, path: bytes) -> int:
        self._log("request_body_from_file", path)
        return self._fail_rc("request_body_from_file")

    def coraza_add_get_args(self, tx: Any, name: bytes, value: bytes) -> int:
        self._log("add_get_args", name, value)
        return self._fail_rc("add_get_args")

    def coraza_update_status_code(self, tx: Any, status: int) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.response_status = int(status)
        self._log("update_status_code", int(status))
        return 0

    def coraza_add_response_header(
        self, tx: Any, name: bytes, name_len: int, value: bytes, value_len: int
    ) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            nm = bytes(name[:name_len]).decode("utf-8", errors="replace")
            vl = bytes(value[:value_len]).decode("utf-8", errors="replace")
            state.response_headers.append((nm, vl))
        self._log("add_response_header")
        return self._fail_rc("add_response_header")

    def coraza_process_response_headers(self, tx: Any, status: int, protocol: bytes) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.response_headers_processed = True
            state.response_status = int(status)
            if (
                self.trigger_response_headers_status is not None
                and int(status) == self.trigger_response_headers_status
            ):
                state.interruption_spec = self.interruption_spec
        self._log("process_response_headers", int(status))
        if state and state.interruption_spec is not None and not state.intervention_served:
            return 1
        return self._fail_rc("process_response_headers")

    def coraza_append_response_body(self, tx: Any, chunk: bytes, length: int) -> int:
        state = self.txs.get(id(tx))
        data = bytes(chunk[:length]) if length else b""
        if state is not None:
            state.response_body.append(data)
            if (
                self.trigger_response_body_contains
                and self.trigger_response_body_contains in data
            ):
                state.interruption_spec = self.interruption_spec
        self._log("append_response_body", length)
        return self._fail_rc("append_response_body")

    def coraza_process_response_body(self, tx: Any) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.response_body_processed = True
        self._log("process_response_body")
        if state and state.interruption_spec is not None and not state.intervention_served:
            return 1
        return self._fail_rc("process_response_body")

    def coraza_is_response_body_processable(self, tx: Any) -> int:
        self._log("is_response_body_processable")
        return 1 if self.response_body_processable else 0

    def coraza_process_logging(self, tx: Any) -> int:
        state = self.txs.get(id(tx))
        if state is not None:
            state.logged = True
        self._log("process_logging")
        return self._fail_rc("process_logging")

    def coraza_intervention(self, tx: Any) -> Any:
        state = self.txs.get(id(tx))
        if state is None or state.interruption_spec is None or state.intervention_served:
            self._log("intervention_none")
            return None
        spec = state.interruption_spec
        state.intervention_served = True
        ptr = _InterventionPtr(
            action=_FakeCData(spec.action.encode("utf-8")),
            data=_FakeCData(spec.data.encode("utf-8")),
            status=spec.status,
            rule_id=spec.rule_id,
            disruptive=spec.disruptive,
            pause=spec.pause,
        )
        self._log("intervention", spec.rule_id)
        return ptr

    def coraza_free_intervention(self, ptr: Any) -> int:
        self._log("free_intervention")
        return 0

    def coraza_add_error_callback(self, cfg: Any, cb: Any, _userdata: Any) -> int:
        self.configs[id(cfg)].error_callback = cb
        self._log("set_error_callback")
        return self._fail_rc("set_error_callback")

    def coraza_add_debug_log_callback(self, cfg: Any, cb: Any, _userdata: Any) -> int:
        self.configs[id(cfg)].debug_callback = cb
        self._log("set_debug_log_callback")
        return self._fail_rc("set_debug_log_callback")

    def coraza_matched_rule_get_error_log(self, handle: Any) -> Any:
        data = getattr(handle, "_bytes", b"")
        self._log("matched_rule_get_error_log")
        return _FakeCData(data or b"fake error log")

    def coraza_matched_rule_get_severity(self, handle: Any) -> int:
        self._log("matched_rule_get_severity")
        return 3


def install_fake_bindings() -> FakeLib:
    """Register the fake `pycoraza._bindings` module in `sys.modules`.

    Called from `tests/conftest.py` before any `pycoraza.*` import.
    Idempotent: replaces the lib inside the existing module so tests
    can reset state without bouncing importers.
    """
    lib = FakeLib()
    module = sys.modules.get("pycoraza._bindings")
    if module is None:
        module = types.ModuleType("pycoraza._bindings")
        sys.modules["pycoraza._bindings"] = module
    module.ffi = lib._ffi
    module.lib = lib
    module.__all__ = ["ffi", "lib"]
    # Point __path__ at the real package dir so integration suites can
    # locate `pycoraza._bindings._pycoraza` (the compiled extension)
    # without us having to fully remove the fake from sys.modules.
    import pathlib
    real_pkg = pathlib.Path(__file__).resolve().parent.parent / "src" / "pycoraza" / "_bindings"
    module.__path__ = [str(real_pkg)] if real_pkg.is_dir() else []
    return lib


__all__ = [
    "FakeLib",
    "_FakeCData",
    "_FakeFFI",
    "_InterventionPtr",
    "_InterventionSpec",
    "install_fake_bindings",
]
