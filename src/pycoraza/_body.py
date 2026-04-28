"""Shared body-buffering primitives for the Flask, Starlette, and Django adapters.

The naive path — read the entire request body into a `bytes` object,
pass it to Coraza, then replay it for the downstream app — doubles
memory per request (one copy for the WAF, one for the app). Under load
that allocator churn dominates: a 100 MB upload at 1 k RPS allocates
~200 GB/s.

This module bounds that cost. ``buffer_request_body`` reads in chunks
and:

  * keeps everything in RAM up to ``BodyLimits.max_in_memory``,
  * spools the overflow to a ``tempfile.SpooledTemporaryFile`` (default
    ``max_in_memory`` rolling threshold) up to ``BodyLimits.max_total``,
  * trips ``exceeded_total`` once we've read past ``max_total`` so the
    caller can apply ``BodyLimits.on_overflow``.

Each chunk is fed to a caller-supplied ``append_to_tx`` callback as
soon as it is read so libcoraza sees the body in the same shape it
arrives — important for streaming-detection rules. The replay reader
is a fresh stream so the downstream app sees a byte-identical body.

The helper is intentionally agnostic about the source iterator: each
adapter wires up the right reader (WSGI ``wsgi.input``, ASGI
``receive``, Django ``HttpRequest`` stream).
"""

from __future__ import annotations

import io
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import IO, Protocol

from .types import BodyLimits

# How much we read from the source per pull. A 64 KiB read is the
# Linux pipe buffer ceiling and matches what gunicorn / uvicorn use
# on their socket recv path — bigger reads add latency without RPS.
_DEFAULT_CHUNK = 64 * 1024


class _AppendCallback(Protocol):
    """Receives every chunk the WAF should see, in source order."""

    def __call__(self, chunk: bytes) -> None: ...


@dataclass(slots=True)
class BufferedBody:
    """Result of buffering a request body under a `BodyLimits` budget.

    ``replay`` is a fresh, seekable read source for the downstream
    application — either an ``io.BytesIO`` (small body) or the
    underlying ``SpooledTemporaryFile`` rewound to position 0. Callers
    must close it via ``close()`` once the request finishes; failing
    to close leaks the temp-file fd until the GC runs.

    ``waf_bytes`` is what we fed to Coraza, in order. For
    ``on_overflow="evaluate_partial"`` this is the truncated prefix;
    everywhere else it equals the full body. ``total_bytes`` is the
    full size we *read* (capped at ``max_total + 1`` once we trip).
    """

    replay: IO[bytes]
    total_bytes: int
    exceeded_total: bool
    waf_truncated: bool

    def close(self) -> None:
        try:
            self.replay.close()
        except Exception:
            pass


def buffer_request_body(
    source: Iterable[bytes] | Iterator[bytes],
    *,
    limits: BodyLimits,
    append_to_tx: _AppendCallback,
) -> BufferedBody:
    """Buffer ``source`` into RAM-then-spool, feeding chunks into the WAF.

    The caller decides what ``source`` is — Flask wraps
    ``environ["wsgi.input"]``, Starlette wraps the ASGI ``receive``,
    Django wraps the request stream. We treat every iterator the same
    so spool/RAM split logic lives in one place.

    Behavior is:

      1. Pull a chunk. If empty we're done.
      2. If feeding it to the WAF would not push past ``max_total``,
         call ``append_to_tx(chunk)`` and stage it for the replay buffer.
         If we exceed ``max_total``, stop calling ``append_to_tx`` (so
         ``evaluate_partial`` mode honors the cap) but keep counting
         ``total_bytes``.
      3. While total staged bytes ≤ ``max_in_memory``, accumulate
         in a list of bytes. On crossing the threshold, flush into a
         ``SpooledTemporaryFile`` whose internal RAM ceiling matches
         ``max_in_memory`` (so the on-disk spill happens at exactly the
         budget we promised).

    A truncated chunk (``len(chunk) > remaining``) gets sliced rather
    than dropped — Coraza's regexes anchor mid-chunk so partial bytes
    still contribute. We never *over*-feed the WAF: every byte staged
    is also a byte stored for replay.
    """
    if limits.max_in_memory < 0 or limits.max_total < 0:
        raise ValueError("BodyLimits values must be non-negative")
    if limits.max_in_memory > limits.max_total:
        raise ValueError("max_in_memory must be <= max_total")

    fed_to_waf = 0
    total_read = 0
    exceeded = False
    waf_truncated = False

    in_ram: list[bytes] = []
    spool: tempfile.SpooledTemporaryFile[bytes] | None = None

    def _stage(chunk: bytes) -> None:
        nonlocal spool
        if spool is not None:
            spool.write(chunk)
            return
        in_ram.append(chunk)
        if sum(len(p) for p in in_ram) > limits.max_in_memory:
            # SpooledTemporaryFile MUST outlive this function — the
            # caller reads it back as the replay stream. Closing here
            # via a context manager would corrupt the request lifecycle.
            spool = tempfile.SpooledTemporaryFile(  # noqa: SIM115
                max_size=limits.max_in_memory, mode="w+b"
            )
            for piece in in_ram:
                spool.write(piece)
            in_ram.clear()

    for raw in source:
        if not raw:
            continue
        chunk = bytes(raw)
        total_read += len(chunk)

        # Phase 1: still under the WAF cap — feed everything we can.
        if fed_to_waf < limits.max_total:
            remaining_for_waf = limits.max_total - fed_to_waf
            if len(chunk) <= remaining_for_waf:
                append_to_tx(chunk)
                _stage(chunk)
                fed_to_waf += len(chunk)
            else:
                # Slice exactly at the cap. Bytes before the slice
                # are scanned by the WAF; bytes after are forwarded
                # only when ``on_overflow="evaluate_partial"`` (the
                # caller decides whether to drain the rest).
                head = chunk[:remaining_for_waf]
                tail = chunk[remaining_for_waf:]
                if head:
                    append_to_tx(head)
                    _stage(head)
                    fed_to_waf += len(head)
                _stage(tail)
                waf_truncated = True
                exceeded = True
        else:
            # Phase 2: WAF cap already hit. Keep staging for replay
            # so ``evaluate_partial`` and ``skip`` callers can still
            # forward the full body — the policy split happens at
            # the call site, not here. ``waf_truncated`` flips on
            # FIRST entry into phase 2 so cap-aligned chunk boundaries
            # are reported the same as mid-chunk slices.
            waf_truncated = True
            exceeded = True
            _stage(chunk)

    if spool is not None:
        spool.seek(0)
        replay: IO[bytes] = spool
    else:
        replay = io.BytesIO(b"".join(in_ram))

    return BufferedBody(
        replay=replay,
        total_bytes=total_read,
        exceeded_total=exceeded,
        waf_truncated=waf_truncated,
    )


def chunked_reader(
    stream: IO[bytes] | None,
    *,
    content_length: int | None = None,
    chunk_size: int = _DEFAULT_CHUNK,
) -> Iterator[bytes]:
    """Pull bytes from a blocking stream in fixed-size chunks.

    Wraps ``wsgi.input`` and Django's ``HttpRequest`` body stream. The
    ``content_length`` cap matters because some WSGI servers don't
    EOF a fixed-length stream — they expect the consumer to stop at
    Content-Length. ``None`` means read until the stream returns ``b""``.
    """
    if stream is None:
        return
    remaining = content_length if content_length is not None else None
    while True:
        if remaining is not None:
            if remaining <= 0:
                return
            to_read = min(chunk_size, remaining)
        else:
            to_read = chunk_size
        chunk = stream.read(to_read)
        if not chunk:
            return
        if remaining is not None:
            remaining -= len(chunk)
        yield chunk


def empty_replay() -> IO[bytes]:
    """Stand-in replay stream for requests with no body.

    Used by the adapters when CONTENT_LENGTH is zero or absent — saves
    the tempfile-fd cost we'd otherwise pay on every GET.
    """
    return io.BytesIO(b"")


def iter_replay(
    stream: IO[bytes], *, chunk_size: int = _DEFAULT_CHUNK
) -> Iterator[bytes]:
    """Yield ``stream``'s bytes for the downstream app.

    Used by the ASGI adapter to emit ``http.request`` messages with
    ``more_body=True`` until the final chunk. Rewinds first so callers
    don't have to track read state.
    """
    try:
        stream.seek(0)
    except (AttributeError, io.UnsupportedOperation):
        pass
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            return
        yield chunk


def resolve_limits(arg: BodyLimits | None) -> BodyLimits:
    """``None`` means defaults — every adapter calls this once at __init__."""
    return arg if arg is not None else BodyLimits()


# Keep the public surface tiny — adapters import these by name and any
# new symbol crosses a contract line that's worth a deliberate re-export.
__all__ = [
    "BufferedBody",
    "buffer_request_body",
    "chunked_reader",
    "empty_replay",
    "iter_replay",
    "resolve_limits",
]


# Re-export the type so adapters can `from .._body import OverflowDecision`
# alongside the helpers. Defined here so the dispatch logic that consumes
# it lives next to the buffering primitive that produced its inputs.
@dataclass(slots=True, frozen=True)
class OverflowDecision:
    """What an adapter should do after reading the body.

    Encodes the outcome of ``BodyLimits.on_overflow`` against the
    actual ``BufferedBody`` so the adapter only has to switch on this
    enum-like flag, never on the policy string. ``feed_truncated``
    means we already fed Coraza the partial prefix and now want to
    forward the full (truncated-on-disk) body downstream.
    """

    pass_through: bool
    block_413: bool
    feed_truncated: bool


def decide_overflow(buffered: BufferedBody, limits: BodyLimits) -> OverflowDecision:
    """Translate `BodyLimits.on_overflow` into a structured decision.

    Splitting this out keeps every adapter's overflow branch shaped the
    same way and makes the policy table easy to audit:

      * not exceeded → no decision needed (pass through, no action)
      * exceeded + ``block`` → 413, do NOT call downstream
      * exceeded + ``skip`` → bypass WAF, forward full body
      * exceeded + ``evaluate_partial`` → forward full body, accept
        Coraza saw a truncated prefix
    """
    if not buffered.exceeded_total:
        return OverflowDecision(pass_through=True, block_413=False, feed_truncated=False)
    action = limits.on_overflow
    if action == "block":
        return OverflowDecision(pass_through=False, block_413=True, feed_truncated=False)
    if action == "skip":
        return OverflowDecision(pass_through=True, block_413=False, feed_truncated=False)
    if action == "evaluate_partial":
        return OverflowDecision(pass_through=True, block_413=False, feed_truncated=True)
    # Unknown literal → fail-closed.
    return OverflowDecision(pass_through=False, block_413=True, feed_truncated=False)


__all__.extend(["OverflowDecision", "decide_overflow"])
