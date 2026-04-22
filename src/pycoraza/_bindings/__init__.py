"""Private: compiled cffi extension lives here.

At runtime this is:
    _pycoraza<ABI>.so  — the cffi API-mode extension built by native/build_ffi.py

Never import the extension module directly from consumer code; always go
through `pycoraza.abi`, which owns the Python↔C lifetime rules.
"""

from __future__ import annotations

try:  # pragma: no cover - import-time smoke test only
    from ._pycoraza import ffi as _ffi  # type: ignore[attr-defined]
    from ._pycoraza import lib as _lib  # type: ignore[attr-defined]
except ImportError as exc:  # pragma: no cover - surfaces to user
    raise ImportError(
        "pycoraza: native extension '_pycoraza' not found. "
        "Install the wheel or run ./native/scripts/build-libcoraza.sh "
        "and `pip install -e .` from the repo root."
    ) from exc


ffi = _ffi
lib = _lib

__all__ = ["ffi", "lib"]
