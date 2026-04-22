"""Public data types for pycoraza.

These dataclasses are the stable surface adapters and user code build
against. Everything else in the package is implementation detail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .logger import Logger


class ProcessMode(str, Enum):
    """Whether a WAF blocks or only logs on rule match."""

    DETECT = "detect"
    BLOCK = "block"


class OnWAFError(str, Enum):
    """Adapter behavior when the WAF raises an exception evaluating a request."""

    BLOCK = "block"
    ALLOW = "allow"


@dataclass(slots=True)
class WAFConfig:
    """Inputs to `create_waf`.

    Parallel to `@coraza/core`'s `WAFConfig` — see coraza-node's
    packages/core/src/types.ts. Rules are SecLang directives, either
    handwritten or emitted by `pycoraza.coreruleset.recommended()` and
    friends.
    """

    rules: str
    mode: ProcessMode = ProcessMode.DETECT
    logger: "Logger | None" = None


@dataclass(slots=True, frozen=True)
class Interruption:
    """A rule interrupted the transaction. Produced by `Transaction.interruption()`."""

    rule_id: int
    action: str
    status: int
    data: str
    source: str | None = None


@dataclass(slots=True, frozen=True)
class MatchedRule:
    """One rule that matched during a transaction."""

    id: int
    severity: int
    message: str


@dataclass(slots=True)
class RequestInfo:
    """HTTP request metadata passed into Coraza for phase 1+2 evaluation."""

    method: str
    url: str
    headers: "Iterable[tuple[str, str]]"
    protocol: str = "HTTP/1.1"
    remote_addr: str = ""
    remote_port: int = 0
    server_port: int = 0


@dataclass(slots=True)
class ResponseInfo:
    """HTTP response metadata passed into Coraza for phase 3+4 evaluation."""

    status: int
    headers: "Iterable[tuple[str, str]]"
    protocol: str = "HTTP/1.1"


@dataclass(slots=True)
class SkipOptions:
    """Static-asset bypass knobs shared across every adapter."""

    extensions: tuple[str, ...] = (
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
        ".mp3", ".mp4", ".webm", ".wav", ".ogg",
        ".pdf", ".zip", ".tar", ".gz",
    )
    prefixes: tuple[str, ...] = (
        "/static/",
        "/assets/",
        "/_next/static/",
        "/favicon.ico",
    )
    extra_paths: tuple[str, ...] = field(default_factory=tuple)


__all__ = [
    "Interruption",
    "MatchedRule",
    "OnWAFError",
    "ProcessMode",
    "RequestInfo",
    "ResponseInfo",
    "SkipOptions",
    "WAFConfig",
]
