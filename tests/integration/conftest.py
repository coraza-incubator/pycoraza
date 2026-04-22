"""Integration-only conftest: ensures the REAL `pycoraza._bindings`
replaces any fake bindings installed by the top-level conftest.

Every test in this directory requires the compiled native extension.
Without it, the module-level skip in each test file takes effect.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


def _find_native_extension() -> bool:
    """Look for the compiled cffi extension on disk, bypassing any fake."""
    pkg_root = Path(__file__).resolve().parents[2] / "src" / "pycoraza" / "_bindings"
    if not pkg_root.is_dir():
        return False
    return any(pkg_root.glob("_pycoraza*.so")) or any(pkg_root.glob("_pycoraza*.pyd"))


_HAS_NATIVE = _find_native_extension()


def _reset_abi_singleton() -> None:
    abi = sys.modules.get("pycoraza.abi")
    if abi is not None:
        abi._INITIALIZED = False
        abi._BINDINGS = None


@pytest.fixture(autouse=True)
def _real_bindings() -> Iterator[None]:
    """Temporarily swap the fake `ffi`/`lib` for the real ones.

    We keep the existing `pycoraza._bindings` module object in
    `sys.modules` (so class identity in already-imported pycoraza modules
    stays stable) and just rebind its `ffi` and `lib` attributes to the
    real native extension. Saved state is restored on teardown so the
    unit-level autouse fixture's fake wins again for subsequent tests.
    """
    if not _HAS_NATIVE:
        yield
        return

    bindings = sys.modules.get("pycoraza._bindings")
    original_ffi = getattr(bindings, "ffi", None) if bindings else None
    original_lib = getattr(bindings, "lib", None) if bindings else None

    real = importlib.import_module("pycoraza._bindings._pycoraza")
    if bindings is not None:
        bindings.ffi = real.ffi
        bindings.lib = real.lib
    _reset_abi_singleton()
    try:
        yield
    finally:
        if bindings is not None and original_ffi is not None and original_lib is not None:
            bindings.ffi = original_ffi
            bindings.lib = original_lib
        _reset_abi_singleton()
