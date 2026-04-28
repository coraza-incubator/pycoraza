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

Hook ordering inside `initialize`:
  1. Ensure CRS rules are present (so the wheel ships them).
  2. If `LIBCORAZA_PREFIX` is unset and we're not under cibuildwheel,
     build libcoraza locally — needed for source installs on platforms
     without a manylinux wheel (Alpine/musl, custom distros).
  3. Compile the cffi extension against the resolved prefix.
"""

from __future__ import annotations

import os
import shutil
import subprocess
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
RULES_DIR = REPO_ROOT / "src" / "pycoraza" / "coreruleset" / "rules"
BUILD_SCRIPT = HERE / "scripts" / "build-libcoraza.sh"
VERSION_FILE = HERE / "version.txt"


def _libcoraza_prefix() -> Path:
    env = os.environ.get("LIBCORAZA_PREFIX")
    if env:
        return Path(env)
    return REPO_ROOT / "build" / "libcoraza"


def _crs_already_fetched() -> bool:
    if not RULES_DIR.is_dir():
        return False
    inner = RULES_DIR / "rules"
    if not inner.is_dir():
        return False
    return any(inner.glob("REQUEST-*.conf"))


def _ensure_crs() -> None:
    """Populate `src/pycoraza/coreruleset/rules/` if empty.

    For sdist installs, the CRS files arrive in the tarball already
    (sdist hook fetches them). This check is a safety net for editable
    installs and direct `pip install <repo>` paths where the repo
    might not have CRS pre-fetched.
    """
    if _crs_already_fetched():
        return
    if not VERSION_FILE.is_file():
        raise RuntimeError(f"version manifest missing at {VERSION_FILE}")
    script = f"""
set -euo pipefail
source "{VERSION_FILE}"
rules_dir="{RULES_DIR}"
if [[ -f "${{rules_dir}}/.crs-tag" ]] \\
    && [[ "$(cat "${{rules_dir}}/.crs-tag")" == "${{CRS_TAG}}" ]]; then
  exit 0
fi
echo "fetching OWASP coreruleset ${{CRS_TAG}}"
mkdir -p "${{rules_dir}}"
tmp="$(mktemp -d)"
curl -fsSL \\
  "https://github.com/coreruleset/coreruleset/archive/refs/tags/${{CRS_TAG}}.tar.gz" \\
  | tar -C "${{tmp}}" -xzf -
rm -rf "${{rules_dir}}/rules" "${{rules_dir}}/crs-setup.conf.example" \\
       "${{rules_dir}}/REQUEST-"*.conf "${{rules_dir}}/RESPONSE-"*.conf 2>/dev/null || true
src="${{tmp}}/coreruleset-${{CRS_TAG#v}}"
cp -R "${{src}}/rules" "${{rules_dir}}/rules"
cp "${{src}}/crs-setup.conf.example" "${{rules_dir}}/crs-setup.conf.example"
echo "${{CRS_TAG}}" > "${{rules_dir}}/.crs-tag"
rm -rf "${{tmp}}"
"""
    subprocess.run(["bash", "-c", script], check=True)


def _ensure_libcoraza() -> Path:
    """Resolve `LIBCORAZA_PREFIX`, building libcoraza locally if needed.

    Source-install path: when `LIBCORAZA_PREFIX` is unset and we're not
    inside cibuildwheel (which runs `before-all` to pre-build), invoke
    `native/scripts/build-libcoraza.sh` to compile libcoraza into
    `<repo>/build/libcoraza/`. Requires Go 1.25+ on PATH.
    """
    env_prefix = os.environ.get("LIBCORAZA_PREFIX")
    if env_prefix:
        return Path(env_prefix)
    if os.environ.get("CIBUILDWHEEL") == "1":
        # cibuildwheel sets LIBCORAZA_PREFIX in the environment; if it's
        # missing here something is wrong with the matrix config.
        return _libcoraza_prefix()
    prefix = REPO_ROOT / "build" / "libcoraza"
    artifact = prefix / "lib" / "libcoraza.so"
    if artifact.is_file():
        os.environ["LIBCORAZA_PREFIX"] = str(prefix)
        return prefix
    if shutil.which("go") is None:
        raise RuntimeError(
            "pycoraza requires Go 1.25+ when building from sdist; "
            "install Go or use a manylinux wheel "
            "(`pip install --only-binary=:all: pycoraza`)."
        )
    if not BUILD_SCRIPT.is_file():
        raise RuntimeError(
            f"build script missing at {BUILD_SCRIPT}; cannot build libcoraza"
        )
    env = os.environ.copy()
    env["LIBCORAZA_PREFIX"] = str(prefix)
    subprocess.run(["bash", str(BUILD_SCRIPT)], check=True, env=env)
    os.environ["LIBCORAZA_PREFIX"] = str(prefix)
    return prefix


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
    """Hatchling build hook — compiles the cffi extension into the wheel.

    Also responsible for ensuring CRS rules are present and libcoraza is
    available before the cffi compile runs; see module docstring.
    """

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        _ensure_crs()
        _ensure_libcoraza()
        # Stage into hatch's build dir so repeated rebuilds don't fight
        # over a shared on-disk tree.
        staging = Path(self.directory) / "pycoraza-ffi-staging"
        out = compile_extension(staging)
        rel = out.relative_to(REPO_ROOT / "src")
        build_data["force_include"][str(out)] = str(rel)
        build_data.setdefault("pure_python", False)
        build_data.setdefault("infer_tag", True)


if __name__ == "__main__":
    _ensure_crs()
    _ensure_libcoraza()
    staging = REPO_ROOT / "build" / "ffi-staging"
    out = compile_extension(staging)
    sys.stdout.write(f"built: {out}\n")
