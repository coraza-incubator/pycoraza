"""`build_skip_predicate` — static-asset bypass semantics."""

from __future__ import annotations

from pycoraza import SkipOptions, build_skip_predicate


class TestDefaults:
    def test_none_yields_default_predicate(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("/static/app.js") is True
        assert skip("/favicon.ico") is True
        assert skip("/api/login") is False

    def test_true_yields_default_predicate(self) -> None:
        skip = build_skip_predicate(True)
        assert skip("/assets/logo.png") is True
        assert skip("/api/users") is False

    def test_extensions_are_case_insensitive(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("/Foo.PNG") is True
        assert skip("/Foo.JPEG") is True
        assert skip("/foo.CSS") is True

    def test_empty_path_is_not_skipped(self) -> None:
        skip = build_skip_predicate(None)
        assert skip("") is False


class TestFalse:
    def test_disables_all_skipping(self) -> None:
        skip = build_skip_predicate(False)
        assert skip("/static/app.js") is False
        assert skip("/favicon.ico") is False
        assert skip("/api/login") is False


class TestCallable:
    def test_user_callable_returned_as_is(self) -> None:
        def mine(path: str) -> bool:
            return path.startswith("/skip-me/")

        skip = build_skip_predicate(mine)
        assert skip("/skip-me/a") is True
        assert skip("/no") is False


class TestSkipOptions:
    def test_custom_options(self) -> None:
        opts = SkipOptions(
            extensions=(".txt",),
            prefixes=("/bypass/",),
            extra_paths=("/healthz",),
        )
        skip = build_skip_predicate(opts)
        assert skip("/bypass/anything") is True
        assert skip("/doc.txt") is True
        assert skip("/healthz") is True
        assert skip("/api/users") is False
        assert skip("/foo.png") is False

    def test_extra_paths_exact_match_only(self) -> None:
        opts = SkipOptions(
            extensions=(), prefixes=(), extra_paths=("/healthz",)
        )
        skip = build_skip_predicate(opts)
        assert skip("/healthz") is True
        assert skip("/healthz/sub") is False
