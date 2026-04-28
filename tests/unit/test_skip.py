"""`build_skip_predicate` — static-asset bypass semantics."""

from __future__ import annotations

from pycoraza import (
    PROBE_METHODS,
    PROBE_PATHS,
    SkipOptions,
    build_skip_predicate,
)


class TestDefaults:
    def test_none_yields_default_predicate(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("GET", "/static/app.js") is True
        assert skip("GET", "/favicon.ico") is True
        assert skip("GET", "/api/login") is False

    def test_true_yields_default_predicate(self) -> None:
        skip = build_skip_predicate(True)
        assert skip("GET", "/assets/logo.png") is True
        assert skip("GET", "/api/users") is False

    def test_extensions_are_case_insensitive(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("GET", "/Foo.PNG") is True
        assert skip("GET", "/Foo.JPEG") is True
        assert skip("GET", "/foo.CSS") is True

    def test_empty_path_is_not_skipped(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("GET", "") is False

    def test_probes_not_skipped_by_default(self) -> None:
        skip = build_skip_predicate(None)
        for probe in PROBE_PATHS:
            assert skip("GET", probe) is False, f"{probe} should NOT skip by default"

    def test_probe_methods_not_skipped_by_default(self) -> None:
        skip = build_skip_predicate(None)
        for m in PROBE_METHODS:
            assert skip(m, "/anything") is False, f"{m} should NOT skip by default"


class TestFalse:
    def test_disables_all_skipping(self) -> None:
        skip = build_skip_predicate(False)
        assert skip("GET", "/static/app.js") is False
        assert skip("GET", "/favicon.ico") is False
        assert skip("GET", "/api/login") is False


class TestCallable:
    def test_user_callable_returned_as_is(self) -> None:
        def mine(method: str, path: str) -> bool:
            return path.startswith("/skip-me/")

        skip = build_skip_predicate(mine)
        assert skip("GET", "/skip-me/a") is True
        assert skip("POST", "/no") is False


class TestSkipOptions:
    def test_custom_options(self) -> None:
        opts = SkipOptions(
            extensions=(".txt",),
            prefixes=("/bypass/",),
            extra_paths=("/healthz",),
        )
        skip = build_skip_predicate(opts)
        assert skip("GET", "/bypass/anything") is True
        assert skip("GET", "/doc.txt") is True
        assert skip("GET", "/healthz") is True
        assert skip("GET", "/api/users") is False
        assert skip("GET", "/foo.png") is False

    def test_extra_paths_exact_match_only(self) -> None:
        opts = SkipOptions(
            extensions=(), prefixes=(), extra_paths=("/healthz",)
        )
        skip = build_skip_predicate(opts)
        assert skip("GET", "/healthz") is True
        assert skip("GET", "/healthz/sub") is False


class TestProbePreset:
    def test_opt_in_via_extra_paths(self) -> None:
        opts = SkipOptions(
            extensions=(), prefixes=(), extra_paths=PROBE_PATHS
        )
        skip = build_skip_predicate(opts)
        for probe in PROBE_PATHS:
            assert skip("GET", probe) is True

    def test_opt_in_methods(self) -> None:
        opts = SkipOptions(
            extensions=(), prefixes=(), methods=PROBE_METHODS
        )
        skip = build_skip_predicate(opts)
        assert skip("OPTIONS", "/api/anything") is True
        assert skip("HEAD", "/api/anything") is True
        assert skip("GET", "/api/anything") is False
        assert skip("POST", "/api/anything") is False

    def test_method_matching_case_insensitive(self) -> None:
        opts = SkipOptions(
            extensions=(), prefixes=(), methods=("HEAD",)
        )
        skip = build_skip_predicate(opts)
        assert skip("head", "/x") is True
        assert skip("Head", "/x") is True

    def test_combined_probes_and_methods(self) -> None:
        opts = SkipOptions(
            prefixes=SkipOptions.default_prefixes(),
            extra_paths=PROBE_PATHS,
            methods=PROBE_METHODS,
        )
        skip = build_skip_predicate(opts)
        assert skip("GET", "/static/app.js") is True
        assert skip("GET", "/healthz") is True
        assert skip("OPTIONS", "/api/whatever") is True
        assert skip("GET", "/api/sensitive") is False


class TestDocstringSemantics:
    """Coverage for coraza-node #28: documented semantics of build_skip_predicate.

    These tests assert the docstring spells out the load-bearing
    behaviors a user must understand before relying on the predicate.
    They guard against silent removals during future refactors.
    """

    def test_docstring_mentions_case_insensitive(self) -> None:
        doc = build_skip_predicate.__doc__ or ""
        assert "case-insensitive" in doc.lower()

    def test_docstring_mentions_compound_extensions(self) -> None:
        doc = build_skip_predicate.__doc__ or ""
        # the .tar.gz example is the explicit illustration in the spec
        assert ".tar.gz" in doc.lower() or "compound" in doc.lower()

    def test_docstring_warns_skip_is_not_security_boundary(self) -> None:
        doc = build_skip_predicate.__doc__ or ""
        lower = doc.lower()
        assert "security" in lower
        # Either "not a security boundary" or "performance optimization"
        # phrasing is acceptable — both are present in the spec.
        assert "performance" in lower or "boundary" in lower

    def test_docstring_documents_path_only_not_query(self) -> None:
        doc = build_skip_predicate.__doc__ or ""
        lower = doc.lower()
        assert "query" in lower or "path only" in lower

    def test_docstring_documents_callable_contract(self) -> None:
        doc = build_skip_predicate.__doc__ or ""
        assert "(method" in doc and "path" in doc
