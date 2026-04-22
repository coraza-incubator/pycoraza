"""Shared fixtures.

Installs the in-memory fake bindings before any `pycoraza.*` module
imports, then resets `pycoraza.abi`'s module-level singleton between
tests so the fake lib is picked up fresh.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _fake_abi import FakeLib, install_fake_bindings  # noqa: E402


_fake = install_fake_bindings()


def _reset_abi_singleton() -> None:
    """Force `pycoraza.abi._bindings()` to re-read the fake module."""
    abi = sys.modules.get("pycoraza.abi")
    if abi is not None:
        abi._INITIALIZED = False
        abi._BINDINGS = None


@pytest.fixture(autouse=True)
def fake_abi() -> Iterator[FakeLib]:
    """A fresh FakeLib for every test, wired into `pycoraza._bindings`."""
    lib = install_fake_bindings()
    _reset_abi_singleton()
    yield lib
    _reset_abi_singleton()


@pytest.fixture
def mock_lib(fake_abi: FakeLib) -> FakeLib:
    """Alias — some tests prefer the name `mock_lib`."""
    return fake_abi


@pytest.fixture
def make_waf(fake_abi: FakeLib) -> Any:
    """Factory: construct a WAF with the given rules + mode."""
    from pycoraza import ProcessMode, WAFConfig, create_waf

    created: list[Any] = []

    def _factory(
        rules: str = "SecRuleEngine On\n",
        mode: ProcessMode = ProcessMode.BLOCK,
        logger: Any = None,
    ) -> Any:
        cfg = WAFConfig(rules=rules, mode=mode, logger=logger)
        waf = create_waf(cfg)
        created.append(waf)
        return waf

    yield _factory
    for waf in created:
        try:
            waf.close()
        except Exception:
            pass
