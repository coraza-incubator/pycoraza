"""`pycoraza.client_ip` — preset and trusted-proxy semantics."""

from __future__ import annotations

import pytest

from pycoraza import DEFAULT_PRIVATE_CIDRS, trusted_proxy
from pycoraza.client_ip import (
    _asgi_header,
    _get_header,
    _is_trusted,
    _is_valid_ip,
    _parse_networks,
    _split_xff,
    _wsgi_header,
    resolve_extractor,
)


def _wsgi_environ(remote_addr: str = "10.0.0.1", **headers: str) -> dict:
    env = {
        "REQUEST_METHOD": "GET",
        "REMOTE_ADDR": remote_addr,
        "wsgi.input": object(),
    }
    for name, value in headers.items():
        env["HTTP_" + name.upper().replace("-", "_")] = value
    return env


def _asgi_scope(client_ip: str = "10.0.0.1", **headers: str) -> dict:
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in headers.items()
    ]
    return {
        "type": "http",
        "method": "GET",
        "headers": raw_headers,
        "client": (client_ip, 12345),
    }


class TestSplitXff:
    def test_single_ip(self) -> None:
        assert _split_xff("203.0.113.5") == ["203.0.113.5"]

    def test_comma_separated(self) -> None:
        assert _split_xff("203.0.113.5, 10.0.0.1, 10.0.0.2") == [
            "203.0.113.5",
            "10.0.0.1",
            "10.0.0.2",
        ]

    def test_extra_whitespace(self) -> None:
        assert _split_xff("  203.0.113.5  ,   10.0.0.1   ") == [
            "203.0.113.5",
            "10.0.0.1",
        ]

    def test_empty_string(self) -> None:
        assert _split_xff("") == []

    def test_only_whitespace_and_commas(self) -> None:
        assert _split_xff("  ,  ,  ") == []

    def test_strips_ipv4_port(self) -> None:
        assert _split_xff("203.0.113.5:55123, 10.0.0.1:443") == [
            "203.0.113.5",
            "10.0.0.1",
        ]

    def test_keeps_invalid_token_as_is(self) -> None:
        # Validation happens later — _split_xff just tokenizes.
        assert _split_xff("not-an-ip, 10.0.0.1") == ["not-an-ip", "10.0.0.1"]

    def test_bracketed_ipv6(self) -> None:
        assert _split_xff("[2001:db8::1]:443, 10.0.0.1") == [
            "2001:db8::1",
            "10.0.0.1",
        ]

    def test_unbracketed_ipv6_kept(self) -> None:
        assert _split_xff("2001:db8::1, 10.0.0.1") == [
            "2001:db8::1",
            "10.0.0.1",
        ]


class TestIsValidIp:
    def test_ipv4(self) -> None:
        assert _is_valid_ip("203.0.113.5") is True

    def test_ipv6(self) -> None:
        assert _is_valid_ip("2001:db8::1") is True

    def test_ipv6_loopback(self) -> None:
        assert _is_valid_ip("::1") is True

    def test_invalid(self) -> None:
        assert _is_valid_ip("not-an-ip") is False
        assert _is_valid_ip("") is False
        assert _is_valid_ip("999.999.999.999") is False


class TestIsTrusted:
    def test_v4_inside_default_set(self) -> None:
        nets = _parse_networks(DEFAULT_PRIVATE_CIDRS)
        assert _is_trusted("10.0.0.5", nets) is True
        assert _is_trusted("172.20.5.5", nets) is True
        assert _is_trusted("192.168.1.1", nets) is True
        assert _is_trusted("127.0.0.1", nets) is True

    def test_v4_outside_default_set(self) -> None:
        nets = _parse_networks(DEFAULT_PRIVATE_CIDRS)
        assert _is_trusted("203.0.113.5", nets) is False
        assert _is_trusted("8.8.8.8", nets) is False

    def test_v6_inside_default_set(self) -> None:
        nets = _parse_networks(DEFAULT_PRIVATE_CIDRS)
        assert _is_trusted("::1", nets) is True
        assert _is_trusted("fd00::1", nets) is True

    def test_v6_outside_default_set(self) -> None:
        nets = _parse_networks(DEFAULT_PRIVATE_CIDRS)
        assert _is_trusted("2001:db8::1", nets) is False

    def test_invalid_ip_is_not_trusted(self) -> None:
        nets = _parse_networks(DEFAULT_PRIVATE_CIDRS)
        assert _is_trusted("not-an-ip", nets) is False

    def test_v4_v6_address_family_isolation(self) -> None:
        # An IPv4 address must not be considered trusted by an IPv6 net.
        nets = _parse_networks(("::1/128",))
        assert _is_trusted("127.0.0.1", nets) is False


class TestHeaderLookup:
    def test_wsgi_header_present(self) -> None:
        env = _wsgi_environ(**{"X-Forwarded-For": "203.0.113.5"})
        assert _wsgi_header(env, "X-Forwarded-For") == "203.0.113.5"

    def test_wsgi_header_missing(self) -> None:
        env = _wsgi_environ()
        assert _wsgi_header(env, "X-Forwarded-For") is None

    def test_wsgi_header_non_string_returns_none(self) -> None:
        env = {"REQUEST_METHOD": "GET", "HTTP_X_FOO": 42}
        assert _wsgi_header(env, "X-Foo") is None

    def test_asgi_header_present(self) -> None:
        scope = _asgi_scope(**{"X-Forwarded-For": "203.0.113.5"})
        assert _asgi_header(scope, "X-Forwarded-For") == "203.0.113.5"

    def test_asgi_header_missing(self) -> None:
        scope = _asgi_scope()
        assert _asgi_header(scope, "X-Forwarded-For") is None

    def test_get_header_branches_wsgi(self) -> None:
        env = _wsgi_environ(**{"CF-Connecting-IP": "1.2.3.4"})
        assert _get_header(env, "CF-Connecting-IP") == "1.2.3.4"

    def test_get_header_branches_asgi(self) -> None:
        scope = _asgi_scope(**{"CF-Connecting-IP": "1.2.3.4"})
        assert _get_header(scope, "CF-Connecting-IP") == "1.2.3.4"

    def test_get_header_non_dict_returns_none(self) -> None:
        assert _get_header(object(), "X-Forwarded-For") is None

    def test_get_header_unrecognized_dict_falls_back_wsgi_then_asgi(self) -> None:
        ambiguous = {"HTTP_X_FOO": "wsgi-value"}
        assert _get_header(ambiguous, "X-Foo") == "wsgi-value"
        ambiguous = {"headers": [(b"x-foo", b"asgi-value")]}
        assert _get_header(ambiguous, "X-Foo") == "asgi-value"
        assert _get_header({}, "X-Foo") is None


class TestTrustedProxyDefault:
    def test_returns_first_untrusted_from_right(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.7, 10.0.0.1"},
        )
        assert extract(env) == "203.0.113.9"

    def test_skips_only_trailing_trusted(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 198.51.100.5, 10.0.0.1"},
        )
        # Walk right-to-left: 10.0.0.1 trusted, 198.51.100.5 untrusted -> return.
        assert extract(env) == "198.51.100.5"

    def test_all_trusted_falls_back_to_remote_addr(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "10.0.0.7, 10.0.0.8, 192.168.1.1"},
        )
        assert extract(env) == "10.0.0.1"

    def test_missing_xff_falls_back_to_remote_addr(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(remote_addr="10.0.0.1")
        assert extract(env) == "10.0.0.1"

    def test_empty_xff_falls_back_to_remote_addr(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(remote_addr="10.0.0.1", **{"X-Forwarded-For": "   ,  "})
        assert extract(env) == "10.0.0.1"

    def test_invalid_entries_skipped(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "garbage, 203.0.113.9, 10.0.0.1"},
        )
        assert extract(env) == "203.0.113.9"

    def test_works_with_asgi_scope(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        scope = _asgi_scope(
            client_ip="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
        )
        assert extract(scope) == "203.0.113.9"


class TestTrustedProxyCustom:
    def test_custom_header(self) -> None:
        extract = trusted_proxy(
            header="X-Real-IP-Chain",
            trusted_cidrs=DEFAULT_PRIVATE_CIDRS,
        )
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Real-IP-Chain": "203.0.113.9, 10.0.0.5"},
        )
        assert extract(env) == "203.0.113.9"

    def test_custom_trusted_cidrs_includes_alb_range(self) -> None:
        extract = trusted_proxy(
            trusted_cidrs=("203.0.113.0/24", "10.0.0.0/8"),
        )
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "198.51.100.7, 203.0.113.9, 10.0.0.5"},
        )
        # 10.0.0.5 trusted, 203.0.113.9 trusted, 198.51.100.7 not trusted -> return.
        assert extract(env) == "198.51.100.7"

    def test_empty_trusted_cidrs_returns_rightmost(self) -> None:
        extract = trusted_proxy(trusted_cidrs=())
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.5"},
        )
        assert extract(env) == "10.0.0.5"


class TestIPv6:
    def test_ipv6_remote_addr_passthrough(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(remote_addr="2001:db8::1")
        assert extract(env) == "2001:db8::1"

    def test_ipv6_in_xff_chain(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="::1",
            **{"X-Forwarded-For": "2001:db8::5, ::1"},
        )
        assert extract(env) == "2001:db8::5"

    def test_ipv6_loopback_treated_as_trusted(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="::1",
            **{"X-Forwarded-For": "2001:db8::5, ::1, ::1"},
        )
        assert extract(env) == "2001:db8::5"

    def test_ipv6_only_trusted_chain_falls_back(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="::1",
            **{"X-Forwarded-For": "::1, fd00::1"},
        )
        assert extract(env) == "::1"


class TestPresetXffFirst:
    def test_returns_leftmost(self) -> None:
        extract = resolve_extractor("xff_first")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.7"},
        )
        assert extract(env) == "203.0.113.9"

    def test_skips_invalid_leading(self) -> None:
        extract = resolve_extractor("xff_first")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "garbage, 203.0.113.9"},
        )
        assert extract(env) == "203.0.113.9"

    def test_no_header_falls_back(self) -> None:
        extract = resolve_extractor("xff_first")
        assert extract is not None
        env = _wsgi_environ(remote_addr="10.0.0.1")
        assert extract(env) == "10.0.0.1"

    def test_works_for_asgi(self) -> None:
        extract = resolve_extractor("xff_first")
        assert extract is not None
        scope = _asgi_scope(
            client_ip="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.7"},
        )
        assert extract(scope) == "203.0.113.9"


class TestPresetXffLast:
    def test_returns_rightmost(self) -> None:
        extract = resolve_extractor("xff_last")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "10.0.0.7, 203.0.113.9"},
        )
        assert extract(env) == "203.0.113.9"

    def test_skips_invalid_trailing(self) -> None:
        extract = resolve_extractor("xff_last")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, garbage"},
        )
        assert extract(env) == "203.0.113.9"

    def test_no_header_falls_back(self) -> None:
        extract = resolve_extractor("xff_last")
        assert extract is not None
        env = _wsgi_environ(remote_addr="10.0.0.1")
        assert extract(env) == "10.0.0.1"


class TestPresetCloudflare:
    def test_uses_cf_connecting_ip(self) -> None:
        extract = resolve_extractor("cloudflare")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{
                "CF-Connecting-IP": "203.0.113.9",
                "X-Forwarded-For": "192.0.2.1, 10.0.0.1",
            },
        )
        assert extract(env) == "203.0.113.9"

    def test_falls_back_to_xff_first(self) -> None:
        extract = resolve_extractor("cloudflare")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
        )
        assert extract(env) == "203.0.113.9"

    def test_invalid_cf_header_falls_through(self) -> None:
        extract = resolve_extractor("cloudflare")
        assert extract is not None
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{
                "CF-Connecting-IP": "garbage",
                "X-Forwarded-For": "203.0.113.9",
            },
        )
        assert extract(env) == "203.0.113.9"

    def test_no_headers_falls_back_to_remote_addr(self) -> None:
        extract = resolve_extractor("cloudflare")
        assert extract is not None
        env = _wsgi_environ(remote_addr="10.0.0.1")
        assert extract(env) == "10.0.0.1"

    def test_works_for_asgi(self) -> None:
        extract = resolve_extractor("cloudflare")
        assert extract is not None
        scope = _asgi_scope(
            client_ip="10.0.0.1",
            **{"CF-Connecting-IP": "203.0.113.9"},
        )
        assert extract(scope) == "203.0.113.9"


class TestResolveExtractor:
    def test_none_returns_none(self) -> None:
        assert resolve_extractor(None) is None

    def test_callable_passed_through(self) -> None:
        def custom(_req: object) -> str:
            return "1.2.3.4"

        assert resolve_extractor(custom) is custom

    def test_unknown_preset_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="unknown extract_client_ip preset"):
            resolve_extractor("xff_middle")

    def test_non_str_non_callable_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="extract_client_ip must be"):
            resolve_extractor(42)  # type: ignore[arg-type]


class TestRemoteAddrFallback:
    def test_no_remote_addr_no_xff(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = {"REQUEST_METHOD": "GET"}
        assert extract(env) == ""

    def test_asgi_no_client_field(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        scope = {"type": "http", "headers": []}
        assert extract(scope) == ""

    def test_remote_addr_non_dict_returns_empty(self) -> None:
        from pycoraza.client_ip import _remote_addr

        assert _remote_addr(object()) == ""

    def test_remote_addr_non_string_value(self) -> None:
        from pycoraza.client_ip import _remote_addr

        assert _remote_addr({"REMOTE_ADDR": 12345}) == ""

    def test_remote_addr_empty_client_tuple(self) -> None:
        from pycoraza.client_ip import _remote_addr

        assert _remote_addr({"client": ()}) == ""


class TestAsgiHeaderEdge:
    def test_asgi_header_decode_error_returns_none(self) -> None:
        # _asgi_header tolerates header values that aren't bytes (an
        # AttributeError on .decode shouldn't propagate to the caller).
        scope = {"type": "http", "headers": [(b"x-forwarded-for", 12345)]}
        assert _asgi_header(scope, "X-Forwarded-For") is None


class TestTrustedProxyInvalidOnlyChain:
    def test_only_invalid_entries_falls_back(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "not-an-ip, also-bad"},
        )
        assert extract(env) == "10.0.0.1"


class TestTrustedProxyRequiresCIDRs:
    def test_call_without_trusted_cidrs_raises(self) -> None:
        with pytest.raises(ValueError, match="trusted_cidrs"):
            trusted_proxy()

    def test_error_message_mentions_default_alias(self) -> None:
        with pytest.raises(ValueError) as exc:
            trusted_proxy()
        assert "DEFAULT_PRIVATE_CIDRS" in str(exc.value)
        assert "docs" in str(exc.value).lower()

    def test_explicit_default_private_cidrs_works(self) -> None:
        extract = trusted_proxy(trusted_cidrs=DEFAULT_PRIVATE_CIDRS)
        env = _wsgi_environ(
            remote_addr="10.0.0.1",
            **{"X-Forwarded-For": "203.0.113.9, 10.0.0.7"},
        )
        assert extract(env) == "203.0.113.9"
