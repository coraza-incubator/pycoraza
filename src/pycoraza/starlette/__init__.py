"""ASGI middleware — covers Starlette, FastAPI, any ASGI framework.

Parallels `@coraza/fastify` and `@coraza/express` in behavior:

  * `on_waf_error="block"` by default — fail closed.
  * `inspect_response=False` by default.
  * `skip` bypasses static assets.
  * Body reading buffers the entire request body before handing to the
    downstream app, then replays it through the receive channel.

Runs Coraza's synchronous C calls via a single `asyncio.to_thread`
per request phase. libcoraza's Go runtime releases the GIL, so
concurrent workers can run the WAF in parallel; the limiting factor
in practice is Python's default thread-pool size (40 tokens on
anyio). Raise `thread_limit` on construction to scale past that.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Any

from .._body import (
    BufferedBody,
    iter_replay,
    resolve_limits,
)
from ..abi import CorazaError
from ..client_ip import ClientIPArg, ClientIPExtractor, resolve_extractor
from ..skip import SkipArg, build_skip_predicate, normalize_path_for_skip
from ..types import (
    BodyLimits,
    Interruption,
    OnWAFError,
    OnWAFErrorArg,
    ProcessMode,
    RequestInfo,
    WAFLike,
)

if TYPE_CHECKING:
    from ..transaction import Transaction

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

OnBlockAsync = Callable[[Interruption, Scope, Send], Awaitable[bool]]


@dataclass(slots=True)
class _RequestResult:
    tx: Transaction
    interrupted: bool
    interruption: Interruption | None
    matched_rules: list
    buffered: BufferedBody


class CorazaMiddleware:
    """ASGI middleware.

    Starlette: `Middleware(CorazaMiddleware, waf=waf)`.
    FastAPI:   `api.add_middleware(CorazaMiddleware, waf=waf)`.

    The `thread_limit` kwarg controls how many concurrent WAF
    evaluations the process will run. Under heavy concurrency (100+
    simultaneous requests) the default anyio thread-pool of 40 becomes
    the bottleneck. Set `thread_limit=None` to leave anyio's default in
    place, an int to install a dedicated `CapacityLimiter`.

    `inspect_response=True` enforces phase-3/4 disruptions by buffering
    the response start + body until both phases have run. SSE / chunked
    downloads are buffered fully when inspection is enabled — that's
    the only correct way to enforce a phase-3/4 block in ASGI.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        waf: WAFLike,
        on_block: OnBlockAsync | None = None,
        inspect_response: bool = False,
        on_waf_error: OnWAFErrorArg = OnWAFError.BLOCK,
        skip: SkipArg = None,
        thread_limit: int | None = None,
        extract_client_ip: ClientIPArg = None,
        body_limits: BodyLimits | None = None,
    ) -> None:
        self._app = app
        self._waf = waf
        self._on_block = on_block
        self._inspect_response = inspect_response
        self._on_waf_error = _normalize_on_waf_error(on_waf_error)
        self._skip = build_skip_predicate(skip)
        self._extract_client_ip: ClientIPExtractor | None = resolve_extractor(extract_client_ip)
        if thread_limit is None:
            thread_limit = max(64, (os.cpu_count() or 4) * 8)
        self._thread_limit = thread_limit
        self._semaphore = asyncio.Semaphore(thread_limit)
        self._body_limits = resolve_limits(body_limits)

    async def _run_in_thread(self, fn, /, *args):
        async with self._semaphore:
            return await asyncio.to_thread(fn, *args)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "") or ""
        method = scope.get("method", "GET")
        # Normalize before skip-matching: ``/admin;.png`` must NOT
        # match the ``.png`` extension skip — Starlette's path
        # converter ignores the ``;...`` segment when dispatching, so
        # the request still hits the ``/admin`` route.
        if self._skip(method, normalize_path_for_skip(path)):
            await self._app(scope, receive, send)
            return

        request_info = _request_info_from_scope(scope, self._extract_client_ip)

        # Step 1: spool the body off the async receive channel before
        # touching the WAF. Doing this first means the WAF phase-1+2
        # call only sees a sync iterator pulling from a bounded buffer
        # — no event-loop bouncing per chunk, no full-body memory
        # spike, and the spool fd is reusable for the downstream replay.
        spool_stream, total_read = await _spool_async_body(receive, self._body_limits)

        try:
            result = await self._run_in_thread(
                _evaluate_request_streaming,
                self._waf,
                request_info,
                spool_stream,
                total_read,
                self._body_limits,
            )
        except CorazaError as exc:
            await self._handle_waf_error(
                scope, receive, send, exc, request_info, spool_stream
            )
            return

        tx = result.tx
        buffered = result.buffered

        # 413 path: the body is past max_total under the default
        # ``block`` policy. Refuse before the downstream app runs.
        if buffered.exceeded_total and self._body_limits.on_overflow == "block":
            self._waf.logger.warning(
                "body limit exceeded — blocking",
                bytes=buffered.total_bytes,
                limit=self._body_limits.max_total,
                policy="block",
            )
            await _send_413(send)
            buffered.close()
            await self._finalize(tx)
            return

        if result.interrupted and result.interruption is not None and self._waf.mode is ProcessMode.BLOCK:
            _log_block(self._waf.logger, result.interruption, result.matched_rules)
            if not await _call_on_block_async(self._on_block, result.interruption, scope, send):
                await _default_block_response(result.interruption, send)
            buffered.close()
            await self._finalize(tx)
            return

        if buffered.exceeded_total and self._body_limits.on_overflow == "skip":
            self._waf.logger.warning(
                "body limit exceeded — bypassing WAF",
                bytes=buffered.total_bytes,
                limit=self._body_limits.max_total,
                policy="skip",
            )
            replay_receive = _replay_receive_from_stream(receive, buffered.replay)
            try:
                await self._app(scope, replay_receive, send)
            finally:
                buffered.close()
                await self._finalize(tx)
            return

        if buffered.waf_truncated:
            self._waf.logger.warning(
                "body limit exceeded — partial WAF inspection",
                bytes=buffered.total_bytes,
                limit=self._body_limits.max_total,
                policy="evaluate_partial",
            )

        replay_receive = _replay_receive_from_stream(receive, buffered.replay)
        wrapped_send = _wrap_send(
            send,
            tx,
            self._inspect_response,
            self._waf.mode,
            self._run_in_thread,
            logger=self._waf.logger,
        )
        try:
            await self._app(scope, replay_receive, wrapped_send.send)
        finally:
            buffered.close()
            await self._finalize(tx)

    async def _finalize(self, tx: Transaction) -> None:
        try:
            await self._run_in_thread(_finalize_tx, tx)
        except CorazaError:
            pass

    async def _handle_waf_error(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        exc: Exception,
        request_info: RequestInfo,
        spool_stream: IO[bytes],
    ) -> None:
        decision = _resolve_waf_error_decision(self._on_waf_error, exc, request_info)
        if decision is OnWAFError.ALLOW:
            # Receive has already been drained into ``spool_stream``.
            # Replay the buffered body to the downstream app so
            # allow-on-error is actually honored end-to-end. Bounded
            # by whatever body limit the upstream server enforced; we
            # never read more than the client sent.
            replay = _replay_receive_from_stream(receive, spool_stream)
            try:
                await self._app(scope, replay, send)
            finally:
                try:
                    spool_stream.close()
                except Exception:
                    pass
            return
        try:
            spool_stream.close()
        except Exception:
            pass
        await send({
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": b"waf error"})


def _normalize_on_waf_error(arg: OnWAFErrorArg) -> OnWAFError | Callable[..., Any]:
    """Coerce the ctor argument into an enum or pass the callable through."""
    if isinstance(arg, OnWAFError):
        return arg
    if isinstance(arg, str):
        return OnWAFError(arg)
    if callable(arg):
        return arg
    raise TypeError(f"on_waf_error must be 'block', 'allow', or callable, got {type(arg)!r}")


def _resolve_waf_error_decision(
    policy: OnWAFError | Callable[..., Any],
    exc: Exception,
    request_info: RequestInfo,
) -> OnWAFError:
    """Run the user policy callable (if any) and coerce its result.

    Falls back to BLOCK if the callable raises or returns an
    unrecognized value — fail-closed posture extends to the policy
    callable itself.
    """
    if isinstance(policy, OnWAFError):
        return policy
    try:
        result = policy(exc, request_info)
    except Exception:
        return OnWAFError.BLOCK
    if isinstance(result, OnWAFError):
        return result
    if isinstance(result, str):
        try:
            return OnWAFError(result)
        except ValueError:
            return OnWAFError.BLOCK
    return OnWAFError.BLOCK


def _evaluate_request_streaming(
    waf: WAFLike,
    request: RequestInfo,
    spool_stream: IO[bytes],
    total_read: int,
    limits: BodyLimits,
) -> _RequestResult:
    """Run the full phase-1+2 pipeline on a worker thread.

    Batching `new_transaction + process_request_bundle + interruption`
    into ONE thread call eliminates per-phase event-loop round trips.
    On a 50-conn wrk bench this cuts scheduler overhead ~3x vs the
    original "one to_thread per phase" implementation.

    Body bytes come from ``spool_stream`` (already drained off the
    async ``receive`` channel) so the WAF inspects exactly what
    arrived on the wire, in chunked order. ``total_read`` lets us
    short-circuit the spool walker when the body is empty without
    paying the iter_replay rewind cost.

    The matched-rule list is also snapshot here, on the same worker
    thread that drove the cgo callbacks — so the caller has a
    complete picture without bouncing back into the WAF.
    """
    tx = waf.new_transaction()
    try:
        tx.process_connection(
            request.remote_addr or "",
            request.remote_port or 0,
            "",
            request.server_port or 0,
        )
        tx.add_request_headers(request.headers)
        tx.process_uri(request.url, request.method, request.protocol)
        if tx.process_request_headers():
            return _wrap_result(
                tx,
                interrupted=True,
                buffered=BufferedBody(
                    replay=spool_stream,
                    total_bytes=total_read,
                    exceeded_total=False,
                    waf_truncated=False,
                ),
            )

        # Spool was filled with the FULL body so ``skip`` and
        # ``evaluate_partial`` can replay all bytes downstream. The
        # WAF feed cap is enforced here: we only call
        # ``append_request_body`` for the first ``max_total`` bytes.
        exceeded = total_read > limits.max_total
        if total_read == 0:
            buffered = BufferedBody(
                replay=spool_stream,
                total_bytes=0,
                exceeded_total=False,
                waf_truncated=False,
            )
        else:
            # Skip the WAF feed entirely on the ``skip`` overflow path
            # — we're going to forward the body downstream untouched
            # and the operator opted into the coverage gap. This keeps
            # the cgo callbacks' rule chain off the audit log too.
            skip_waf = exceeded and limits.on_overflow == "skip"
            if not skip_waf:
                try:
                    spool_stream.seek(0)
                except (AttributeError, OSError):
                    pass
                fed = 0
                while fed < limits.max_total:
                    want = min(64 * 1024, limits.max_total - fed)
                    chunk = spool_stream.read(want)
                    if not chunk:
                        break
                    tx.append_request_body(chunk)
                    fed += len(chunk)
            buffered = BufferedBody(
                replay=spool_stream,
                total_bytes=total_read,
                exceeded_total=exceeded,
                waf_truncated=exceeded and not skip_waf,
            )

        # Three exit paths from phase 2:
        #   * normal body — run process_request_body
        #   * exceeded + block — caller is going to 413, no need to
        #     process (we already ate the bytes on the way in)
        #   * exceeded + skip — bypass WAF entirely, no process call
        # Only ``evaluate_partial`` still runs phase 2 on the truncated
        # prefix — that's the documented attack-detection gap.
        run_phase2 = (
            not buffered.exceeded_total
            or limits.on_overflow == "evaluate_partial"
        )
        if run_phase2:
            tx.process_request_body()
        return _wrap_result(tx, interrupted=False, buffered=buffered)
    except CorazaError:
        try:
            tx.close()
        except CorazaError:
            pass
        raise


def _wrap_result(
    tx: Transaction, *, interrupted: bool, buffered: BufferedBody
) -> _RequestResult:
    """Snapshot the interruption state on the worker thread.

    Pulled out of the body of ``_evaluate_request_streaming`` so the
    request-headers early-return and the body early-return share one
    construction site — easier to keep `matched_rules` capture honest.
    """
    interrupted = interrupted or tx.interruption() is not None
    intr = tx.interruption() if interrupted else None
    matches = tx.matched_rules() if interrupted else []
    return _RequestResult(
        tx=tx,
        interrupted=interrupted,
        interruption=intr,
        matched_rules=matches,
        buffered=buffered,
    )


def _finalize_tx(tx: Transaction) -> None:
    try:
        tx.process_logging()
    finally:
        tx.close()


async def _spool_async_body(
    receive: Receive, limits: BodyLimits
) -> tuple[IO[bytes], int]:
    """Drain the ASGI receive channel into a spooled tempfile.

    The spool gets EVERY byte the client sends, regardless of
    ``limits.max_total``: the ``skip`` policy forwards the full body
    to the downstream app, which can only happen if we kept it. The
    WAF feed cap is enforced in the worker thread, not here.

    We do honor the spool's RAM-vs-disk threshold (``max_in_memory``)
    so the per-process footprint stays bounded under sustained load,
    and we obviously stop on ``http.disconnect`` — at that point
    there's nothing to forward and ``BodyLimits`` is irrelevant.
    """
    import tempfile

    # Spool fd outlives this function: the eval thread reads back from
    # it, the replay receive iterates it, and the close happens in the
    # request finalizer. A context manager here would close it before
    # the WAF ever sees the bytes.
    spool: tempfile.SpooledTemporaryFile[bytes] = tempfile.SpooledTemporaryFile(  # noqa: SIM115
        max_size=limits.max_in_memory, mode="w+b"
    )
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.request":
            chunk = message.get("body", b"") or b""
            if chunk:
                spool.write(chunk)
                total += len(chunk)
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    spool.seek(0)
    return spool, total


def _replay_receive_from_stream(original: Receive, stream: IO[bytes]) -> Receive:
    """Replay a spooled body through ``receive`` in 64KiB chunks.

    ASGI consumers (Starlette, FastAPI, Mangum) iterate ``receive``
    until ``more_body=False``, then ignore further calls. We emit
    ``more_body=True`` chunks while bytes remain and a final
    ``more_body=False`` chunk to terminate. Streaming chunks (vs. one
    big buffer) keeps the downstream framework from briefly doubling
    a big body in memory — the whole point of the spool.
    """
    try:
        stream.seek(0)
    except (AttributeError, OSError):
        pass
    iterator: Iterator[bytes] | None = None
    pending: bytes | None = None
    finished = False

    def _start() -> Iterator[bytes]:
        return iter_replay(stream, chunk_size=64 * 1024)

    async def receive() -> Message:
        nonlocal iterator, pending, finished
        if finished:
            return await original()
        if iterator is None:
            iterator = _start()
            pending = next(iterator, None)
        # Look one chunk ahead so we can set ``more_body`` correctly
        # without an extra empty-trailer message.
        current = pending
        nxt = next(iterator, None) if iterator is not None else None
        pending = nxt
        if current is None:
            finished = True
            return {"type": "http.request", "body": b"", "more_body": False}
        if nxt is None:
            finished = True
            return {"type": "http.request", "body": current, "more_body": False}
        return {"type": "http.request", "body": current, "more_body": True}

    return receive


async def _send_413(send: Send) -> None:
    payload = b"Payload Too Large"
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(payload)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": payload})


def _request_info_from_scope(
    scope: Scope,
    extract_client_ip: ClientIPExtractor | None = None,
) -> RequestInfo:
    # ASGI ``scope["headers"]`` is a list of ``(bytes, bytes)`` tuples.
    # Repeated request headers (e.g. two ``Cookie`` lines or proxy-split
    # ``X-Forwarded-For``) appear as distinct entries — preserve that
    # by iterating the list rather than collapsing into a dict.
    headers = tuple(
        (k.decode("latin-1").lower(), v.decode("latin-1"))
        for k, v in scope.get("headers", [])
    )
    scheme = scope.get("scheme", "http")
    path = scope.get("path", "") or ""
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, (bytes, bytearray)):
        # Decode as UTF-8 with surrogateescape so non-UTF-8 bytes
        # round-trip cleanly to the WAF instead of expanding into
        # latin-1-then-utf8 mojibake. Starlette's router decodes the
        # raw bytes as UTF-8 at dispatch; we MUST hand Coraza the same
        # bytes the wire carried, or rules keyed on path content miss
        # attacks where the raw bytes contain multi-byte UTF-8 (e.g.
        # the wire bytes for the CJK character at codepoint U+4E2D).
        # ``surrogateescape`` smuggles invalid-UTF-8 bytes through as
        # lone surrogates that ``_utf8`` re-emits as the same bytes.
        path = raw_path.decode("utf-8", errors="surrogateescape") or path
    query = scope.get("query_string", b"") or b""
    host = next((v for k, v in headers if k == "host"), "")
    url = f"{scheme}://{host}{path}"
    if query:
        url = f"{url}?{query.decode('utf-8', errors='surrogateescape')}"

    client = scope.get("client") or ("", 0)
    server = scope.get("server") or ("", 0)
    wire_addr = str(client[0] or "")
    if extract_client_ip is not None:
        try:
            extracted = extract_client_ip(scope)
        except Exception:
            extracted = ""
        remote_addr = extracted or wire_addr
    else:
        remote_addr = wire_addr
    return RequestInfo(
        method=scope.get("method", "GET"),
        url=url,
        headers=headers,
        protocol=f"HTTP/{scope.get('http_version', '1.1')}",
        remote_addr=remote_addr,
        remote_port=int(client[1] or 0),
        server_port=int(server[1] or 0),
    )


async def _call_on_block_async(
    handler: OnBlockAsync | None,
    intr: Interruption,
    scope: Scope,
    send: Send,
) -> bool:
    if handler is None:
        return False
    return bool(await handler(intr, scope, send))


async def _default_block_response(intr: Interruption, send: Send) -> None:
    status = intr.status or 403
    payload = (
        f'{{"error":"blocked","rule_id":{intr.rule_id},'
        f'"action":"{_escape(intr.action)}",'
        f'"msg":"{_escape(intr.data)}",'
        f'"data":"{_escape(intr.data)}",'
        f'"status":{status}}}'
    ).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": payload})


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _log_block(logger: Any, intr: Interruption, matched: list) -> None:
    """Emit the block + every contributing rule.

    `warning` for the disruptive rule (operator headline), `info` for
    each link in the chain — CRS anomaly-score blocks have a 5-10 rule
    chain that the operator needs to see for triage.
    """
    logger.warning(
        "blocked",
        rule_id=intr.rule_id,
        status=intr.status,
        action=intr.action,
        msg=intr.data,
    )
    for rule in matched:
        logger.info(
            "rule chain",
            rule_id=rule.id,
            severity=rule.severity,
            msg=rule.message,
        )


class _WrappedSend:
    """Send wrapper that enforces phase-3/4 interruptions when inspecting.

    With ``inspect=False`` we forward every ``send()`` immediately —
    same shape as before, no buffering.

    With ``inspect=True`` we BUFFER the ``http.response.start`` message
    and every body chunk until ``more_body=False``. Only then do we run
    ``process_response_body`` and consult ``tx.interruption()``. If the
    WAF interrupted AND mode is BLOCK we emit a default block response
    instead; otherwise we replay the buffered messages. Buffering is
    the only correct way to enforce a phase-3/4 block in ASGI: once
    ``http.response.start`` hits the wire, we cannot rescind the
    status or headers. Streaming responses (SSE, chunked downloads)
    are fully buffered when ``inspect_response=True``.
    """

    __slots__ = (
        "_blocked",
        "_buffered_messages",
        "_inspect",
        "_logger",
        "_mode",
        "_real",
        "_response_started",
        "_run",
        "_tx",
    )

    def __init__(
        self,
        real: Send,
        tx: Transaction,
        inspect: bool,
        mode: ProcessMode,
        run: Callable[..., Awaitable[Any]],
        logger: Any = None,
    ) -> None:
        self._real = real
        self._tx = tx
        self._inspect = inspect
        self._mode = mode
        self._run = run
        self._blocked = False
        self._response_started = False
        self._buffered_messages: list[Message] = []
        self._logger = logger

    async def send(self, message: Message) -> None:
        if self._blocked:
            return
        if not self._inspect:
            if message["type"] == "http.response.start":
                self._response_started = True
            await self._real(message)
            return
        await self._send_buffered(message)

    async def _send_buffered(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            status = int(message.get("status", 200))
            # ``message["headers"]`` is a list of ``(bytes, bytes)`` —
            # repeated entries (e.g. multiple ``Set-Cookie`` headers,
            # which RFC 6265 explicitly mandates as separate lines)
            # round-trip as distinct tuples without de-duplication.
            headers = [
                (k.decode("latin-1"), v.decode("latin-1"))
                for k, v in message.get("headers", [])
            ]
            try:
                await self._run(_record_response_headers, self._tx, headers, status)
            except CorazaError:
                pass
            self._buffered_messages.append(message)
            return
        if message["type"] == "http.response.body":
            chunk = message.get("body", b"") or b""
            more = bool(message.get("more_body", False))
            if chunk:
                try:
                    await self._run(self._tx.append_response_body, chunk)
                except CorazaError:
                    pass
            self._buffered_messages.append(message)
            if not more:
                try:
                    await self._run(self._tx.process_response_body)
                except CorazaError:
                    pass
                await self._flush()
            return
        await self._real(message)

    async def _flush(self) -> None:
        if self._mode is ProcessMode.BLOCK:
            try:
                intr = await self._run(self._tx.interruption)
            except CorazaError:
                intr = None
            if intr is not None:
                self._blocked = True
                if self._logger is not None:
                    try:
                        matched = await self._run(self._tx.matched_rules)
                    except CorazaError:
                        matched = []
                    _log_block(self._logger, intr, matched)
                await _default_block_response(intr, self._real)
                self._response_started = True
                return
        for msg in self._buffered_messages:
            if msg["type"] == "http.response.start":
                self._response_started = True
            await self._real(msg)


def _record_response_headers(tx: Transaction, headers, status: int) -> None:
    tx.add_response_headers(headers)
    tx.process_response_headers(status)


def _wrap_send(
    send: Send,
    tx: Transaction,
    inspect: bool,
    mode: ProcessMode,
    run: Callable[..., Awaitable[Any]],
    logger: Any = None,
) -> _WrappedSend:
    return _WrappedSend(send, tx, inspect, mode, run, logger=logger)


__all__ = ["CorazaMiddleware"]
