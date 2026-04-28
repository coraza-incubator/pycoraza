"""Unit tests for the shared body-buffer helper.

Covers the spool/RAM split, WAF feed cap under each ``on_overflow``
policy, and the edge cases (empty body, exact-cap body, multi-chunk
splits).
"""

from __future__ import annotations

import io

import pytest

from pycoraza._body import (
    BufferedBody,
    buffer_request_body,
    chunked_reader,
    decide_overflow,
    empty_replay,
    iter_replay,
    resolve_limits,
)
from pycoraza.types import BodyLimits


def _collect_appends() -> tuple[list[bytes], callable]:
    """Return a list-of-chunks recorder and a matching append callback."""
    seen: list[bytes] = []

    def append(chunk: bytes) -> None:
        seen.append(chunk)

    return seen, append


class TestBufferRequestBody:
    def test_small_body_stays_in_ram(self) -> None:
        seen, append = _collect_appends()
        limits = BodyLimits(max_in_memory=1024, max_total=4096, on_overflow="block")
        body = b"hello world"
        buffered = buffer_request_body(
            iter([body]), limits=limits, append_to_tx=append
        )
        assert seen == [body]
        assert buffered.total_bytes == len(body)
        assert not buffered.exceeded_total
        assert not buffered.waf_truncated
        assert buffered.replay.read() == body

    def test_medium_body_spills_to_spool(self) -> None:
        seen, append = _collect_appends()
        # 2KB max RAM, 64KB total — body fits in spool but past RAM threshold.
        limits = BodyLimits(max_in_memory=2048, max_total=65536, on_overflow="block")
        body = b"A" * 8192
        # Feed in 1KB chunks so we can verify the WAF sees them in order.
        chunks = [body[i : i + 1024] for i in range(0, len(body), 1024)]
        buffered = buffer_request_body(
            iter(chunks), limits=limits, append_to_tx=append
        )
        try:
            assert b"".join(seen) == body
            assert buffered.total_bytes == len(body)
            assert not buffered.exceeded_total
            # Replay must round-trip byte-identical.
            assert buffered.replay.read() == body
        finally:
            buffered.close()

    def test_oversized_body_caps_waf_feed(self) -> None:
        seen, append = _collect_appends()
        limits = BodyLimits(max_in_memory=1024, max_total=4096, on_overflow="block")
        body = b"X" * 8192
        chunks = [body[i : i + 1024] for i in range(0, len(body), 1024)]
        buffered = buffer_request_body(
            iter(chunks), limits=limits, append_to_tx=append
        )
        try:
            # WAF saw the first 4096 bytes only.
            assert sum(len(c) for c in seen) == limits.max_total
            assert b"".join(seen) == body[: limits.max_total]
            assert buffered.exceeded_total
            assert buffered.waf_truncated
            # Replay still has the full body so skip/evaluate_partial can
            # forward downstream.
            assert buffered.replay.read() == body
        finally:
            buffered.close()

    def test_partial_chunk_at_cap_boundary(self) -> None:
        """Chunk slicing at exactly the WAF cap must split, not drop."""
        seen, append = _collect_appends()
        limits = BodyLimits(max_in_memory=8, max_total=10, on_overflow="block")
        # First chunk is 8 bytes (under cap), second is 6 bytes (would push to 14).
        buffered = buffer_request_body(
            iter([b"AAAAAAAA", b"BBBBBB"]),
            limits=limits,
            append_to_tx=append,
        )
        try:
            # Bytes fed to WAF must be exactly first 10.
            assert b"".join(seen) == b"AAAAAAAABB"
            assert buffered.exceeded_total
            assert buffered.waf_truncated
            assert buffered.replay.read() == b"AAAAAAAABBBBBB"
        finally:
            buffered.close()

    def test_invalid_limits_rejected(self) -> None:
        _, append = _collect_appends()
        with pytest.raises(ValueError):
            buffer_request_body(
                iter([b""]),
                limits=BodyLimits(max_in_memory=-1, max_total=10),
                append_to_tx=append,
            )
        with pytest.raises(ValueError):
            buffer_request_body(
                iter([b""]),
                limits=BodyLimits(max_in_memory=100, max_total=10),
                append_to_tx=append,
            )


class TestChunkedReader:
    def test_reads_until_eof_when_no_length(self) -> None:
        stream = io.BytesIO(b"hello world")
        chunks = list(chunked_reader(stream, content_length=None, chunk_size=4))
        assert b"".join(chunks) == b"hello world"
        assert all(len(c) <= 4 for c in chunks)

    def test_respects_content_length(self) -> None:
        stream = io.BytesIO(b"abcdefghij")
        chunks = list(chunked_reader(stream, content_length=5, chunk_size=8))
        assert b"".join(chunks) == b"abcde"

    def test_none_stream_yields_nothing(self) -> None:
        assert list(chunked_reader(None, content_length=10)) == []


class TestIterReplay:
    def test_yields_chunks_from_stream(self) -> None:
        stream = io.BytesIO(b"replay-me")
        chunks = list(iter_replay(stream, chunk_size=4))
        assert b"".join(chunks) == b"replay-me"

    def test_seeks_back_to_zero(self) -> None:
        stream = io.BytesIO(b"abcd")
        stream.read()  # advance past EOF
        chunks = list(iter_replay(stream, chunk_size=2))
        assert b"".join(chunks) == b"abcd"


class TestDecideOverflow:
    def _bb(self, exceeded: bool) -> BufferedBody:
        return BufferedBody(
            replay=empty_replay(),
            total_bytes=0,
            exceeded_total=exceeded,
            waf_truncated=False,
        )

    def test_no_overflow_passes_through(self) -> None:
        d = decide_overflow(self._bb(False), BodyLimits())
        assert d.pass_through and not d.block_413 and not d.feed_truncated

    def test_block_returns_413(self) -> None:
        d = decide_overflow(
            self._bb(True), BodyLimits(on_overflow="block")
        )
        assert d.block_413 and not d.pass_through

    def test_skip_passes_through(self) -> None:
        d = decide_overflow(
            self._bb(True), BodyLimits(on_overflow="skip")
        )
        assert d.pass_through and not d.block_413 and not d.feed_truncated

    def test_evaluate_partial_passes_truncated(self) -> None:
        d = decide_overflow(
            self._bb(True), BodyLimits(on_overflow="evaluate_partial")
        )
        assert d.pass_through and d.feed_truncated and not d.block_413


class TestResolveLimits:
    def test_none_returns_defaults(self) -> None:
        limits = resolve_limits(None)
        assert limits.max_in_memory == 1024 * 1024
        assert limits.max_total == 32 * 1024 * 1024
        assert limits.on_overflow == "block"

    def test_passes_through_explicit(self) -> None:
        custom = BodyLimits(max_in_memory=1, max_total=2, on_overflow="skip")
        assert resolve_limits(custom) is custom
