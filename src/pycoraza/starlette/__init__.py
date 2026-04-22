"""ASGI middleware — covers Starlette, FastAPI, any ASGI framework.

Parallels `@coraza/fastify` and `@coraza/express` in behavior:

  * `on_waf_error="block"` by default — fail closed.
  * `inspect_response=False` by default.
  * `skip` bypasses static assets.
  * Body reading buffers the entire request body before handing to the
    downstream app, then replays it through the receive channel.

Runs Coraza's synchronous C calls via `asyncio.to_thread` so the event
loop doesn't stall on the WAF. libcoraza's Go runtime handles
concurrency under the hood.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from ..abi import CorazaError
from ..skip import SkipArg, build_skip_predicate
from ..types import Interruption, OnWAFError, ProcessMode, RequestInfo

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..waf import WAF

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

OnBlockAsync = Callable[[Interruption, Scope, Send], Awaitable[bool]]


class CorazaMiddleware:
    """ASGI middleware.

    Starlette: `Middleware(CorazaMiddleware, waf=waf)`.
    FastAPI:   `api.add_middleware(CorazaMiddleware, waf=waf)`.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        waf: "WAF",
        on_block: OnBlockAsync | None = None,
        inspect_response: bool = False,
        on_waf_error: OnWAFError | str = OnWAFError.BLOCK,
        skip: SkipArg = None,
    ) -> None:
        self._app = app
        self._waf = waf
        self._on_block = on_block
        self._inspect_response = inspect_response
        self._on_waf_error = (
            on_waf_error if isinstance(on_waf_error, OnWAFError) else OnWAFError(on_waf_error)
        )
        self._skip = build_skip_predicate(skip)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "") or ""
        if self._skip(path):
            await self._app(scope, receive, send)
            return

        try:
            tx = await asyncio.to_thread(self._waf.new_transaction)
        except CorazaError:
            await self._handle_waf_error(scope, send)
            return

        try:
            body = await _read_asgi_body(receive)
            interrupted = await asyncio.to_thread(
                tx.process_request_bundle,
                _request_info_from_scope(scope),
                body,
            )
            if interrupted:
                intr = await asyncio.to_thread(tx.interruption)
                if intr is not None and self._waf.mode is ProcessMode.BLOCK:
                    if not await _call_on_block_async(self._on_block, intr, scope, send):
                        await _default_block_response(intr, send)
                    await _finalize(tx)
                    return
        except CorazaError:
            await _finalize(tx)
            await self._handle_waf_error(scope, send)
            return

        replay_receive = _replay_receive(receive, body)
        wrapped_send = _wrap_send(send, tx, self._inspect_response, self._waf.mode)
        try:
            await self._app(scope, replay_receive, wrapped_send.send)
        finally:
            await _finalize(tx)

    async def _handle_waf_error(self, scope: Scope, send: Send) -> None:
        if self._on_waf_error is OnWAFError.ALLOW:
            raise CorazaError("cannot allow-fall-through after middleware consumed receive")
        await send({
            "type": "http.response.start",
            "status": 500,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": b"waf error"})


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


def _request_info_from_scope(scope: Scope) -> RequestInfo:
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
    return RequestInfo(
        method=scope.get("method", "GET"),
        url=url,
        headers=headers,
        protocol=f"HTTP/{scope.get('http_version', '1.1')}",
        remote_addr=str(client[0] or ""),
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
        f'"data":"{_escape(intr.data)}"}}'
    ).encode("utf-8")
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


class _WrappedSend:
    __slots__ = ("_real", "_tx", "_inspect", "_mode", "_blocked", "_response_started")

    def __init__(self, real: Send, tx: "Transaction", inspect: bool, mode: ProcessMode) -> None:
        self._real = real
        self._tx = tx
        self._inspect = inspect
        self._mode = mode
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
            headers = [
                (k.decode("latin-1"), v.decode("latin-1"))
                for k, v in message.get("headers", [])
            ]
            try:
                await asyncio.to_thread(self._tx.add_response_headers, headers)
                await asyncio.to_thread(self._tx.process_response_headers, status)
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
                    await asyncio.to_thread(self._tx.append_response_body, chunk)
                except CorazaError:
                    pass
            if not more:
                try:
                    await asyncio.to_thread(self._tx.process_response_body)
                except CorazaError:
                    pass
            await self._real(message)
            return
        await self._real(message)


def _wrap_send(send: Send, tx: "Transaction", inspect: bool, mode: ProcessMode) -> _WrappedSend:
    return _WrappedSend(send, tx, inspect, mode)


async def _finalize(tx: "Transaction") -> None:
    try:
        await asyncio.to_thread(tx.process_logging)
    finally:
        await asyncio.to_thread(tx.close)


__all__ = ["CorazaMiddleware"]
