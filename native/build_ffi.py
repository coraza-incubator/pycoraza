"""cffi extension builder — invoked by hatchling at wheel build time.

This module is both:
  * a build hook registered via `[tool.hatch.build.targets.wheel.hooks.custom]`
    in pyproject.toml, so `pip install .` / `cibuildwheel` produce a wheel
    with the compiled `_pycoraza*.so` inside.
  * a standalone script (`python native/build_ffi.py`) for local dev.

The produced extension is `pycoraza._bindings._pycoraza`. It is linked
against libcoraza so that `auditwheel repair` bundles `libcoraza.so`
into `pycoraza.libs/` automatically.

Compile flow note:
  `cffi.FFI.compile(tmpdir=T)` creates `T/<module-path>/_pycoraza*.so`
  — it uses the module name's dots as directory separators. So if the
  module is `pycoraza._bindings._pycoraza`, compiling into
  `src/pycoraza/_bindings/` produces
  `src/pycoraza/_bindings/pycoraza/_bindings/_pycoraza*.so` (nested).
  We compile into a staging dir, then move the final .so to its
  proper home under `src/pycoraza/_bindings/`.
"""

from __future__ import annotations

import os
import shutil
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
BINDINGS_DIR = REPO_ROOT / "src" / "pycoraza" / "_bindings"


def _libcoraza_prefix() -> Path:
    env = os.environ.get("LIBCORAZA_PREFIX")
    if env:
        return Path(env)
    return REPO_ROOT / "build" / "libcoraza"


def _read_cdef() -> str:
    return CDEF_PATH.read_text(encoding="utf-8")


def build_ffi():  # type: ignore[no-untyped-def]
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


def compile_extension(staging_dir: Path) -> Path:
    """Compile the cffi extension and return the final .so path.

    Compiles into `staging_dir`, then moves the extension to
    `src/pycoraza/_bindings/` where `pycoraza._bindings.__init__`
    imports it from. Nested pycoraza/_bindings/ subdirs cffi left
    behind in the staging tree are cleaned up.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    ffi = build_ffi()
    out = Path(ffi.compile(tmpdir=str(staging_dir), verbose=True))

    BINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    final = BINDINGS_DIR / out.name
    shutil.copy2(out, final)

    # Clean up the nested pycoraza/_bindings/ tree cffi created inside
    # staging — we only want the .so at its canonical location.
    leftover = staging_dir / "pycoraza"
    if leftover.exists() and leftover != BINDINGS_DIR.parent:
        shutil.rmtree(leftover, ignore_errors=True)

    return final


class CustomBuildHook(BuildHookInterface):
    """Hatchling build hook — compiles the cffi extension into the wheel."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        # Stage into hatch's build dir so repeated rebuilds don't fight
        # over a shared on-disk tree.
        staging = Path(self.directory) / "pycoraza-ffi-staging"
        out = compile_extension(staging)
        rel = out.relative_to(REPO_ROOT / "src")
        build_data["force_include"][str(out)] = str(rel)
        build_data.setdefault("pure_python", False)
        build_data.setdefault("infer_tag", True)


if __name__ == "__main__":
    staging = REPO_ROOT / "build" / "ffi-staging"
    out = compile_extension(staging)
    sys.stdout.write(f"built: {out}\n")
