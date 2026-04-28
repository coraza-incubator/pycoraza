"""Public data types for pycoraza.

These dataclasses are the stable surface adapters and user code build
against. Everything else in the package is implementation detail.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Literal

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
    logger: Logger | None = None


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
    headers: Iterable[tuple[str, str]]
    protocol: str = "HTTP/1.1"
    remote_addr: str = ""
    remote_port: int = 0
    server_port: int = 0


@dataclass(slots=True)
class ResponseInfo:
    """HTTP response metadata passed into Coraza for phase 3+4 evaluation."""

    status: int
    headers: Iterable[tuple[str, str]]
    protocol: str = "HTTP/1.1"


# Callable form of `on_waf_error`. Adapters invoke this only for WAF
# *errors* (CorazaError raised inside the middleware), NOT for
# rule-driven blocks. Implementers can use it for circuit-breaker
# / per-error-class policies. Return one of the literal strings
# `"block"` or `"allow"`; anything else falls back to BLOCK.
WAFErrorPolicy = Callable[[Exception, "RequestInfo"], Literal["block", "allow"]]

# What an adapter accepts as `on_waf_error`. Mirrors the union signature
# called out in coraza-node #29.
OnWAFErrorArg = OnWAFError | Literal["block", "allow"] | WAFErrorPolicy


@dataclass(slots=True)
class SkipOptions:
    """Static-asset bypass knobs shared across every adapter.

    Defaults only cover static assets — endpoint probes and
    HEAD/OPTIONS are NOT skipped by default because they can carry
    attacker-controlled headers. Opt in by passing `PROBE_PATHS` and/or
    `PROBE_METHODS` (constants exported from `pycoraza`) when you know
    those routes are internal-only:

        from pycoraza import SkipOptions, PROBE_PATHS, PROBE_METHODS
        skip = SkipOptions(prefixes=SkipOptions.default_prefixes() + PROBE_PATHS,
                           methods=PROBE_METHODS)
    """

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
    methods: tuple[str, ...] = field(default_factory=tuple)

    @staticmethod
    def default_prefixes() -> tuple[str, ...]:
        return (
            "/static/",
            "/assets/",
            "/_next/static/",
            "/favicon.ico",
        )


# Opt-in preset: common health / readiness / metrics endpoints. Skipping
# these is a deliberate trade: you lose WAF coverage on paths that are
# almost always unreachable from the internet but can, if misconfigured,
# route to handlers with real logic (e.g. Prometheus pushgateway accepts
# writes at /metrics). Enable only when you have verified the probe
# routes in your app are static or internal-only.
PROBE_PATHS: tuple[str, ...] = (
    "/healthz",
    "/health",
    "/metrics",
    "/readiness",
    "/readyz",
    "/liveness",
    "/livez",
    "/ping",
)

# Opt-in preset: request methods that rarely carry attack bodies. OPTIONS
# CORS preflights can carry attacker-controlled headers; enabling this
# trades that visibility for the CPU savings.
PROBE_METHODS: tuple[str, ...] = ("HEAD", "OPTIONS")


__all__ = [
    "PROBE_METHODS",
    "PROBE_PATHS",
    "Interruption",
    "MatchedRule",
    "OnWAFError",
    "OnWAFErrorArg",
    "ProcessMode",
    "RequestInfo",
    "ResponseInfo",
    "SkipOptions",
    "WAFConfig",
    "WAFErrorPolicy",
]
