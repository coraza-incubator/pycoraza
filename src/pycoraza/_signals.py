"""Go-runtime signal-handler isolation.

libcoraza is `go build -buildmode=c-shared`. On first load, Go installs
handlers for SIGSEGV, SIGBUS, SIGFPE, SIGPIPE, SIGURG, SIGPROF, and
SIGXFSZ. This module documents the interaction and provides a best-
effort helper to re-install Python's `faulthandler` after pycoraza
loads so users can still diagnose crashes.

Rules:
  * Import `pycoraza` before `faulthandler.enable()`.
  * Do not call `signal.signal(signal.SIGPROF, ...)` after import;
    Go's profiler will clobber it.
  * `GODEBUG=asyncpreemptoff=1` disables Go's SIGURG-based preemption
    if it interferes with long-running embeddings. See docs/threat-model.md.
"""

from __future__ import annotations

import logging
import os
import signal

_GO_MANAGED_SIGNALS: frozenset[int] = frozenset(
    s
    for s in (
        getattr(signal, "SIGSEGV", None),
        getattr(signal, "SIGBUS", None),
        getattr(signal, "SIGFPE", None),
        getattr(signal, "SIGPIPE", None),
        getattr(signal, "SIGURG", None),
        getattr(signal, "SIGPROF", None),
        getattr(signal, "SIGXFSZ", None),
    )
    if s is not None
)


def snapshot_handlers() -> dict[int, object]:
    """Capture current signal handlers. Call before loading libcoraza."""
    return {sig: signal.getsignal(sig) for sig in _GO_MANAGED_SIGNALS}


def audit_after_load(pre: dict[int, object], logger: logging.Logger) -> list[int]:
    """Diff handler state after libcoraza loads. Returns displaced signals."""
    displaced: list[int] = []
    for sig, before in pre.items():
        after = signal.getsignal(sig)
        if before is not None and after is not before:
            displaced.append(sig)
    if displaced:
        logger.warning(
            "pycoraza: Go runtime displaced host signal handlers for %s",
            ", ".join(signal.Signals(s).name for s in displaced),
        )
    return displaced


def apply_asyncpreempt_mitigation() -> None:
    """Disable Go's async SIGURG preemption.

    Only needed if the host already handles SIGURG, or if I/O-bound
    embeddings see unexpected EINTR. Idempotent; appends only.
    """
    current = os.environ.get("GODEBUG", "")
    if "asyncpreemptoff=1" in current:
        return
    joined = f"{current},asyncpreemptoff=1" if current else "asyncpreemptoff=1"
    os.environ["GODEBUG"] = joined


__all__ = [
    "apply_asyncpreempt_mitigation",
    "audit_after_load",
    "snapshot_handlers",
]
