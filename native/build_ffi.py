"""cffi extension builder — invoked by hatchling at wheel build time.

This module is both:
  * a build hook registered via `[tool.hatch.build.targets.wheel.hooks.custom]`
    in pyproject.toml, so `pip install .` / `cibuildwheel` produce a wheel
    with the compiled `_pycoraza*.so` inside.
  * a standalone script (`python native/build_ffi.py`) for local dev.

The produced extension is `pycoraza._bindings._pycoraza`. It is linked
against libcoraza so that `auditwheel repair` bundles `libcoraza.so`
into `pycoraza.libs/` automatically.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # pragma: no cover - hatch not present in dev installs
    BuildHookInterface = object  # type: ignore[assignment,misc]


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
CDEF_PATH = HERE / "coraza_cdef.h"
MODULE_NAME = "pycoraza._bindings._pycoraza"


def _libcoraza_prefix() -> Path:
    env = os.environ.get("LIBCORAZA_PREFIX")
    if env:
        return Path(env)
    return REPO_ROOT / "build" / "libcoraza"


def _read_cdef() -> str:
    return CDEF_PATH.read_text(encoding="utf-8")


def build_ffi() -> "cffi.FFI":  # type: ignore[name-defined]
    import cffi

    prefix = _libcoraza_prefix()
    include_dir = prefix / "include"
    lib_dir = prefix / "lib"

    ffi = cffi.FFI()
    ffi.cdef(_read_cdef())

    ffi.set_source(
        MODULE_NAME,
        '#include "coraza/coraza.h"',
        include_dirs=[str(include_dir)],
        library_dirs=[str(lib_dir)],
        libraries=["coraza"],
        extra_compile_args=["-DPy_LIMITED_API=0x030A0000"],
        extra_link_args=[
            "-Wl,-rpath,$ORIGIN/../../pycoraza.libs",
            "-Wl,-rpath,$ORIGIN",
        ],
        py_limited_api=True,
    )
    return ffi


def compile_extension(target_dir: Path) -> Path:
    ffi = build_ffi()
    target_dir.mkdir(parents=True, exist_ok=True)
    out = ffi.compile(tmpdir=str(target_dir), verbose=True)
    return Path(out)


class CustomBuildHook(BuildHookInterface):
    """Hatchling build hook — compiles the cffi extension into the wheel."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        target = REPO_ROOT / "src" / "pycoraza" / "_bindings"
        out = compile_extension(target)
        rel = out.relative_to(REPO_ROOT / "src")
        build_data["force_include"][str(out)] = str(rel)
        build_data.setdefault("pure_python", False)
        build_data.setdefault("infer_tag", True)


if __name__ == "__main__":
    target = REPO_ROOT / "src" / "pycoraza" / "_bindings"
    out = compile_extension(target)
    sys.stdout.write(f"built: {out}\n")
