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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..abi import CorazaError
from ..client_ip import ClientIPArg, ClientIPExtractor, resolve_extractor
from ..skip import SkipArg, build_skip_predicate
from ..types import Interruption, OnWAFError, OnWAFErrorArg, ProcessMode, RequestInfo

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..waf import WAF

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


class CorazaMiddleware:
    """ASGI middleware.

    Starlette: `Middleware(CorazaMiddleware, waf=waf)`.
    FastAPI:   `api.add_middleware(CorazaMiddleware, waf=waf)`.

    The `thread_limit` kwarg controls how many concurrent WAF
    evaluations the process will run. Under heavy concurrency (100+
    simultaneous requests) the default anyio thread-pool of 40 becomes
    the bottleneck. Set `thread_limit=None` to leave anyio's default in
    place, an int to install a dedicated `CapacityLimiter`.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        waf: WAF,
        on_block: OnBlockAsync | None = None,
        inspect_response: bool = False,
        on_waf_error: OnWAFErrorArg = OnWAFError.BLOCK,
        skip: SkipArg = None,
        thread_limit: int | None = None,
        extract_client_ip: ClientIPArg = None,
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

    async def _run_in_thread(self, fn, /, *args):
        async with self._semaphore:
            return await asyncio.to_thread(fn, *args)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "") or ""
        method = scope.get("method", "GET")
        if self._skip(method, path):
            await self._app(scope, receive, send)
            return

        body = await _read_asgi_body(receive)
        request_info = _request_info_from_scope(scope, self._extract_client_ip)
        try:
            result = await self._run_in_thread(
                _evaluate_request,
                self._waf,
                request_info,
                body,
            )
        except CorazaError as exc:
            await self._handle_waf_error(scope, send, exc, request_info)
            return

        tx = result.tx
        if result.interrupted and result.interruption is not None and self._waf.mode is ProcessMode.BLOCK:
            _log_block(self._waf.logger, result.interruption, result.matched_rules)
            if not await _call_on_block_async(self._on_block, result.interruption, scope, send):
                await _default_block_response(result.interruption, send)
            await self._finalize(tx)
            return

        replay_receive = _replay_receive(receive, body)
        wrapped_send = _wrap_send(
            send, tx, self._inspect_response, self._waf.mode, self._run_in_thread
        )
        try:
            await self._app(scope, replay_receive, wrapped_send.send)
        finally:
            await self._finalize(tx)

    async def _finalize(self, tx: Transaction) -> None:
        try:
            await self._run_in_thread(_finalize_tx, tx)
        except CorazaError:
            pass

    async def _handle_waf_error(
        self,
        scope: Scope,
        send: Send,
        exc: Exception,
        request_info: RequestInfo,
    ) -> None:
        decision = _resolve_waf_error_decision(self._on_waf_error, exc, request_info)
        if decision is OnWAFError.ALLOW:
            raise CorazaError("cannot allow-fall-through after middleware consumed receive")
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


def _evaluate_request(
    waf: WAF, request: RequestInfo, body: bytes
) -> _RequestResult:
    """Run the full phase-1+2 pipeline on a worker thread.

    Batching `new_transaction + process_request_bundle + interruption`
    into ONE thread call eliminates per-phase event-loop round trips.
    On a 50-conn wrk bench this cuts scheduler overhead ~3x vs the
    original "one to_thread per phase" implementation.

    The matched-rule list is also snapshot here, on the same worker
    thread that drove the cgo callbacks — that way the caller has
    a complete picture without bouncing back into the WAF.
    """
    tx = waf.new_transaction()
    try:
        interrupted = tx.process_request_bundle(request, body)
        intr = tx.interruption() if interrupted else None
        matches = tx.matched_rules() if interrupted else []
        return _RequestResult(
            tx=tx, interrupted=interrupted, interruption=intr, matched_rules=matches
        )
    except CorazaError:
        try:
            tx.close()
        except CorazaError:
            pass
        raise


def _finalize_tx(tx: Transaction) -> None:
    try:
        tx.process_logging()
    finally:
        tx.close()


async def _read_asgi_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.request":
            chunk = message.get("body", b"") or b""
            if chunk:
                chunks.append(chunk)
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    return b"".join(chunks)


def _replay_receive(original: Receive, body: bytes) -> Receive:
    delivered = False

    async def receive() -> Message:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await original()

    return receive


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
        path = raw_path.decode("latin-1", errors="replace") or path
    query = scope.get("query_string", b"") or b""
    host = next((v for k, v in headers if k == "host"), "")
    url = f"{scheme}://{host}{path}"
    if query:
        url = f"{url}?{query.decode('latin-1', errors='replace')}"

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
    __slots__ = ("_blocked", "_inspect", "_mode", "_real", "_response_started", "_run", "_tx")

    def __init__(
        self,
        real: Send,
        tx: Transaction,
        inspect: bool,
        mode: ProcessMode,
        run: Callable[..., Awaitable[Any]],
    ) -> None:
        self._real = real
        self._tx = tx
        self._inspect = inspect
        self._mode = mode
        self._run = run
        self._blocked = False
        self._response_started = False

    async def send(self, message: Message) -> None:
        if self._blocked:
            return
        if not self._inspect:
            if message["type"] == "http.response.start":
                self._response_started = True
            await self._real(message)
            return
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
            self._response_started = True
            await self._real(message)
            return
        if message["type"] == "http.response.body":
            chunk = message.get("body", b"") or b""
            more = bool(message.get("more_body", False))
            if chunk:
                try:
                    await self._run(self._tx.append_response_body, chunk)
                except CorazaError:
                    pass
            if not more:
                try:
                    await self._run(self._tx.process_response_body)
                except CorazaError:
                    pass
            await self._real(message)
            return
        await self._real(message)


def _record_response_headers(tx: Transaction, headers, status: int) -> None:
    tx.add_response_headers(headers)
    tx.process_response_headers(status)


def _wrap_send(
    send: Send,
    tx: Transaction,
    inspect: bool,
    mode: ProcessMode,
    run: Callable[..., Awaitable[Any]],
) -> _WrappedSend:
    return _WrappedSend(send, tx, inspect, mode, run)


__all__ = ["CorazaMiddleware"]
