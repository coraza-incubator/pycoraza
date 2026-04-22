"""Logger factories and `Logger` protocol conformance."""

from __future__ import annotations

import logging

import pytest

from pycoraza import Logger, console_logger, silent_logger


class TestSilentLogger:
    def test_implements_protocol(self) -> None:
        log = silent_logger()
        assert isinstance(log, Logger)

    def test_swallows_every_level(self) -> None:
        log = silent_logger()
        assert log.debug("x", a=1) is None
        assert log.info("x") is None
        assert log.warning("x") is None
        assert log.error("x", e="boom") is None


class TestConsoleLogger:
    def test_returns_logger_protocol(self) -> None:
        log = console_logger()
        assert isinstance(log, Logger)

    def test_idempotent_handler_install(self) -> None:
        root = logging.getLogger("pycoraza")
        for handler in list(root.handlers):
            root.removeHandler(handler)
        console_logger()
        console_logger()
        assert len(root.handlers) == 1

    def test_emits_through_stdlib(self, caplog: pytest.LogCaptureFixture) -> None:
        log = console_logger()
        with caplog.at_level(logging.DEBUG, logger="pycoraza"):
            log.info("hello", rule=42)
            log.error("nope", err="boom")
            log.warning("heads up")
            log.debug("tracing")
        messages = [r.getMessage() for r in caplog.records]
        assert "hello" in messages
        assert "nope" in messages
        assert "heads up" in messages
        assert "tracing" in messages

    def test_fields_flow_via_extra(self, caplog: pytest.LogCaptureFixture) -> None:
        log = console_logger()
        with caplog.at_level(logging.INFO, logger="pycoraza"):
            log.info("hello", rule=42, ip="1.2.3.4")
        record = next(r for r in caplog.records if r.getMessage() == "hello")
        assert getattr(record, "pycoraza", {}) == {"rule": 42, "ip": "1.2.3.4"}
