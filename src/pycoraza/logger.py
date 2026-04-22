"""Logger protocol + shipped implementations.

Parallel to `@coraza/core`'s `logger.ts`. Adapters may accept a user
logger or fall back to framework-specific loggers (e.g. Flask's
`app.logger`, Starlette's access log).
"""

from __future__ import annotations

import logging
import sys
from typing import Protocol, runtime_checkable


@runtime_checkable
class Logger(Protocol):
    def debug(self, message: str, /, **fields: object) -> None: ...
    def info(self, message: str, /, **fields: object) -> None: ...
    def warning(self, message: str, /, **fields: object) -> None: ...
    def error(self, message: str, /, **fields: object) -> None: ...


class _StdLogger:
    """Thin adapter over `logging.getLogger("pycoraza")`.

    Keyword args flow through `logging`'s `extra=` dict so structured
    log backends (e.g. `python-json-logger`) can render them.
    """

    __slots__ = ("_inner",)

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._inner = logger or logging.getLogger("pycoraza")

    def debug(self, message: str, /, **fields: object) -> None:
        self._inner.debug(message, extra={"pycoraza": fields})

    def info(self, message: str, /, **fields: object) -> None:
        self._inner.info(message, extra={"pycoraza": fields})

    def warning(self, message: str, /, **fields: object) -> None:
        self._inner.warning(message, extra={"pycoraza": fields})

    def error(self, message: str, /, **fields: object) -> None:
        self._inner.error(message, extra={"pycoraza": fields})


class _SilentLogger:
    """No-op logger; drop-in for tests and quiet deployments."""

    __slots__ = ()

    def debug(self, message: str, /, **fields: object) -> None: return None
    def info(self, message: str, /, **fields: object) -> None: return None
    def warning(self, message: str, /, **fields: object) -> None: return None
    def error(self, message: str, /, **fields: object) -> None: return None


def console_logger() -> Logger:
    """Stdlib logging, INFO+ on stderr. Matches coraza-node's consoleLogger."""
    root = logging.getLogger("pycoraza")
    if not root.handlers:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s pycoraza: %(message)s"))
        root.addHandler(handler)
    if root.level == logging.NOTSET:
        root.setLevel(logging.INFO)
    return _StdLogger(root)


def silent_logger() -> Logger:
    """Drop every event. Matches coraza-node's silentLogger."""
    return _SilentLogger()


__all__ = ["Logger", "console_logger", "silent_logger"]
