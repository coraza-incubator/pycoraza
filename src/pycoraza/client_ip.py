"""Pluggable real-client-IP extraction for adapters.

Behind any reverse proxy (Cloudflare, AWS ALB, Nginx, gunicorn-behind-
proxy), the wire-level remote address is the proxy's IP, not the
client's. CRS rule families that depend on the real client IP — the
REQUEST-913 scanner-detection family, IP allowlists, anomaly scoring —
silently no-op in that situation.

This module exposes a small, opt-in extraction layer. The default
behavior of every adapter is unchanged; users wire it up by passing
`extract_client_ip=` into the adapter middleware.

Three input forms are accepted by the adapters:

  * `None` — today's behavior: trust whatever the server hands us.
  * a built-in preset name: ``"cloudflare"``, ``"xff_first"``,
    ``"xff_last"``.
  * a callable ``(request_or_scope) -> str`` for fully custom
    extraction.

For ALB / Nginx / gunicorn-behind-proxy, the correct algorithm is to
walk the ``X-Forwarded-For`` chain right-to-left and peel off any IP
inside a configured trusted-CIDR set. ``trusted_proxy()`` returns
exactly that callable.

Header access works identically against a Flask/WSGI environ dict and
an ASGI scope dict — the lookup helpers below normalize both.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from typing import Any

DEFAULT_PRIVATE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
    "fd00::/8",
)

ClientIPExtractor = Callable[[Any], str]


def _parse_networks(
    cidrs: Sequence[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


def _is_trusted(
    ip_str: str,
    networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in networks:
        if (
            isinstance(addr, ipaddress.IPv4Address)
            and isinstance(net, ipaddress.IPv4Network)
            and addr in net
        ):
            return True
        if (
            isinstance(addr, ipaddress.IPv6Address)
            and isinstance(net, ipaddress.IPv6Network)
            and addr in net
        ):
            return True
    return False


def _is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return True


def _wsgi_header(environ: dict[str, Any], header_name: str) -> str | None:
    """Lookup an HTTP header in a WSGI environ dict.

    WSGI mangles header names: ``X-Forwarded-For`` becomes
    ``HTTP_X_FORWARDED_FOR``. We accept the canonical header name from
    the caller and normalize.
    """
    key = "HTTP_" + header_name.upper().replace("-", "_")
    value = environ.get(key)
    if isinstance(value, str):
        return value
    return None


def _asgi_header(scope: dict[str, Any], header_name: str) -> str | None:
    """Lookup an HTTP header in an ASGI scope dict.

    ASGI stores headers as a list of ``(bytes, bytes)`` tuples with
    lowercase names. We do a linear scan — header lists are short (<32
    in any sane stack) so a dict cache is overkill.
    """
    target = header_name.lower().encode("latin-1")
    for raw_key, raw_value in scope.get("headers", []) or []:
        if raw_key == target:
            try:
                return raw_value.decode("latin-1")
            except (AttributeError, UnicodeDecodeError):
                return None
    return None


def _get_header(request_or_scope: Any, header_name: str) -> str | None:
    """Header lookup that works against a WSGI environ or ASGI scope.

    WSGI has ``REQUEST_METHOD``; ASGI has ``type``. We branch on that.
    """
    if not isinstance(request_or_scope, dict):
        return None
    if "REQUEST_METHOD" in request_or_scope or "wsgi.input" in request_or_scope:
        return _wsgi_header(request_or_scope, header_name)
    if "type" in request_or_scope and "headers" in request_or_scope:
        return _asgi_header(request_or_scope, header_name)
    val = _wsgi_header(request_or_scope, header_name)
    if val is not None:
        return val
    return _asgi_header(request_or_scope, header_name)


def _remote_addr(request_or_scope: Any) -> str:
    if not isinstance(request_or_scope, dict):
        return ""
    if "REMOTE_ADDR" in request_or_scope:
        val = request_or_scope.get("REMOTE_ADDR")
        return val if isinstance(val, str) else ""
    client = request_or_scope.get("client")
    if isinstance(client, (list, tuple)) and len(client) >= 1:
        return str(client[0] or "")
    return ""


def _split_xff(value: str) -> list[str]:
    """Parse an XFF header value into a list of IPs.

    Tolerates whitespace, IPv6 literals (with or without brackets),
    optional ``:port`` suffix on IPv4 entries.
    """
    out: list[str] = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        if item.startswith("[") and "]" in item:
            inside, _, _ = item[1:].partition("]")
            item = inside.strip()
        elif item.count(":") == 1:
            head, _, _ = item.partition(":")
            if _is_valid_ip(head):
                item = head
        if item:
            out.append(item)
    return out


def trusted_proxy(
    *,
    header: str = "X-Forwarded-For",
    trusted_cidrs: Sequence[str] = DEFAULT_PRIVATE_CIDRS,
) -> ClientIPExtractor:
    """Build a real-client-IP extractor for trusted-proxy chains.

    Walks the configured header (default ``X-Forwarded-For``) right-to-
    left, peeling off any entry whose IP is inside one of the
    ``trusted_cidrs``. Returns the first entry that is NOT trusted —
    that is the originating client.

    Falls back to the wire-level ``REMOTE_ADDR`` / ``scope['client'][0]``
    when:

      * the header is absent or empty,
      * every entry in the chain is trusted (a misconfiguration: a
        request from inside the trusted perimeter has no untrusted
        hop, so the wire-level address is the most informative
        identifier we have).

    The default ``trusted_cidrs`` set covers RFC1918, loopback, and
    fd00::/8. Override it for cloud LB ranges or for partial trust.
    """
    networks = _parse_networks(trusted_cidrs)

    def extract(request_or_scope: Any) -> str:
        raw = _get_header(request_or_scope, header)
        if raw:
            chain = _split_xff(raw)
            for ip in reversed(chain):
                if not _is_valid_ip(ip):
                    continue
                if not _is_trusted(ip, networks):
                    return ip
        return _remote_addr(request_or_scope)

    return extract


def _xff_first() -> ClientIPExtractor:
    """Return the leftmost XFF entry — the de-facto single-trusted-proxy default.

    Correct when there is exactly one trusted proxy in front of the app
    that prepends to ``X-Forwarded-For``. Wrong (and spoofable) when
    the request reaches the app directly, since the client controls the
    header.
    """

    def extract(request_or_scope: Any) -> str:
        raw = _get_header(request_or_scope, "X-Forwarded-For")
        if raw:
            chain = _split_xff(raw)
            for ip in chain:
                if _is_valid_ip(ip):
                    return ip
        return _remote_addr(request_or_scope)

    return extract


def _xff_last() -> ClientIPExtractor:
    """Return the rightmost XFF entry — correct for AWS ALB.

    AWS ALB **appends** the connecting client IP to ``X-Forwarded-For``,
    so the rightmost entry is what the ALB observed on the wire. If
    ``X-Forwarded-For`` is missing entirely we fall through to
    ``REMOTE_ADDR``.
    """

    def extract(request_or_scope: Any) -> str:
        raw = _get_header(request_or_scope, "X-Forwarded-For")
        if raw:
            chain = _split_xff(raw)
            for ip in reversed(chain):
                if _is_valid_ip(ip):
                    return ip
        return _remote_addr(request_or_scope)

    return extract


def _cloudflare() -> ClientIPExtractor:
    """Read ``CF-Connecting-IP`` first, fall back to leftmost XFF.

    Cloudflare sets ``CF-Connecting-IP`` to the client that hit their
    edge. The header is reliable when the origin is configured to
    accept connections only from Cloudflare's IP ranges — without that
    network ACL, the header is spoofable.

    See https://developers.cloudflare.com/fundamentals/reference/http-request-headers/.
    """

    def extract(request_or_scope: Any) -> str:
        raw = _get_header(request_or_scope, "CF-Connecting-IP")
        if raw:
            ip = raw.strip()
            if _is_valid_ip(ip):
                return ip
        raw = _get_header(request_or_scope, "X-Forwarded-For")
        if raw:
            chain = _split_xff(raw)
            for ip in chain:
                if _is_valid_ip(ip):
                    return ip
        return _remote_addr(request_or_scope)

    return extract


_PRESETS: dict[str, Callable[[], ClientIPExtractor]] = {
    "cloudflare": _cloudflare,
    "xff_first": _xff_first,
    "xff_last": _xff_last,
}


ClientIPArg = ClientIPExtractor | str | None


def resolve_extractor(arg: ClientIPArg) -> ClientIPExtractor | None:
    """Normalize the ``extract_client_ip`` adapter kwarg.

    Returns ``None`` for the default (server-supplied REMOTE_ADDR).
    Returns a callable for any preset name or user-supplied callable.
    Raises ``ValueError`` on an unknown preset name.
    """
    if arg is None:
        return None
    if callable(arg):
        return arg
    if isinstance(arg, str):
        try:
            factory = _PRESETS[arg]
        except KeyError:
            raise ValueError(
                f"unknown extract_client_ip preset {arg!r}; "
                f"expected one of {sorted(_PRESETS)} or a callable"
            ) from None
        return factory()
    raise TypeError(
        "extract_client_ip must be None, a preset name, or a callable; "
        f"got {type(arg).__name__}"
    )


__all__ = [
    "DEFAULT_PRIVATE_CIDRS",
    "ClientIPArg",
    "ClientIPExtractor",
    "resolve_extractor",
    "trusted_proxy",
]
