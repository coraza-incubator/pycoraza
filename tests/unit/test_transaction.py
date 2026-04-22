"""`Transaction` lifecycle + fused `process_request_bundle`/`process_response`."""

from __future__ import annotations

import pytest

from _fake_abi import FakeLib

from pycoraza import (
    CorazaError,
    ProcessMode,
    RequestInfo,
    ResponseInfo,
    WAFConfig,
    create_waf,
)


def _make_waf(mode: ProcessMode = ProcessMode.BLOCK):
    return create_waf(WAFConfig(rules="SecRuleEngine On\n", mode=mode))


def _req(
    url: str = "/",
    method: str = "GET",
    body: bytes | None = None,
    headers: tuple[tuple[str, str], ...] = (),
) -> RequestInfo:
    return RequestInfo(
        method=method,
        url=url,
        headers=headers,
        remote_addr="127.0.0.1",
        remote_port=54321,
        server_port=8080,
    )


class TestLifecycle:
    def test_close_idempotent(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        tx.close()
        waf.close()

    def test_handle_after_close_raises(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        with pytest.raises(CorazaError):
            _ = tx.handle
        waf.close()

    def test_context_manager_logs_then_closes(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        with waf.new_transaction() as tx:
            tx.process_connection("1.1.1.1", 10)
        logs = [c[0] for c in fake_abi.call_log]
        assert "process_logging" in logs
        assert "free_transaction" in logs
        waf.close()

    def test_process_logging_noop_after_close(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.close()
        before = list(fake_abi.call_log)
        tx.process_logging()  # must not raise
        assert fake_abi.call_log == before
        waf.close()


class TestRequestPipeline:
    def test_process_request_bundle_happy(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_request_bundle(_req(), body=None)
        assert interrupted is False
        tx.close()
        waf.close()

    def test_process_request_bundle_with_body(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_request_bundle(_req(method="POST"), body=b"hello=1")
        assert ("append_request_body", 7) in fake_abi.call_log
        tx.close()
        waf.close()

    def test_interrupted_via_uri(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_uri_contains = "/attack"
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_request_bundle(_req(url="/attack"))
        assert interrupted is True
        intr = tx.interruption()
        assert intr is not None
        assert intr.status == 403
        tx.close()
        waf.close()

    def test_append_request_body_skips_empty(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.append_request_body(b"")
        assert not any(c[0] == "append_request_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()

    def test_add_request_headers(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.add_request_headers([("X-A", "1"), ("X-B", "2")])
        calls = [c for c in fake_abi.call_log if c[0] == "add_request_header"]
        assert len(calls) == 2
        tx.close()
        waf.close()

    def test_process_uri_custom_protocol(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_uri("/x", "GET", "HTTP/2")
        state = fake_abi.txs[id(tx.handle)]
        assert state.protocol == "HTTP/2"
        tx.close()
        waf.close()


class TestResponsePipeline:
    def test_process_response_happy(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=200, headers=(("Content-Type", "text/html"),)),
            body=b"<html>ok</html>",
        )
        assert interrupted is False
        tx.close()
        waf.close()

    def test_interrupted_at_response_headers(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_response_headers_status = 500
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=500, headers=()), body=b""
        )
        assert interrupted is True
        tx.close()
        waf.close()

    def test_interrupted_at_response_body(self, fake_abi: FakeLib) -> None:
        fake_abi.trigger_response_body_contains = b"leak"
        waf = _make_waf()
        tx = waf.new_transaction()
        interrupted = tx.process_response(
            ResponseInfo(status=200, headers=()), body=b"secret leak here"
        )
        assert interrupted is True
        tx.close()
        waf.close()

    def test_response_body_skipped_when_not_processable(self, fake_abi: FakeLib) -> None:
        fake_abi.response_body_processable = False
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.process_response(
            ResponseInfo(status=200, headers=()), body=b"xxx"
        )
        assert not any(c[0] == "append_response_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()

    def test_update_status_code(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.update_status_code(418)
        assert ("update_status_code", 418) in fake_abi.call_log
        tx.close()
        waf.close()

    def test_add_response_headers(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.add_response_headers([("Server", "pycoraza"), ("X", "Y")])
        calls = [c for c in fake_abi.call_log if c[0] == "add_response_header"]
        assert len(calls) == 2
        tx.close()
        waf.close()

    def test_append_response_body_empty_is_noop(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        tx.append_response_body(b"")
        assert not any(c[0] == "append_response_body" for c in fake_abi.call_log)
        tx.close()
        waf.close()


class TestInterruptionAccessor:
    def test_returns_none_without_match(self, fake_abi: FakeLib) -> None:
        waf = _make_waf()
        tx = waf.new_transaction()
        assert tx.interruption() is None
        tx.close()
        waf.close()
