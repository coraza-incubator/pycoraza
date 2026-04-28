"""Sdist build hook — fetch OWASP CRS rules before packaging.

`python -m build --sdist` does not run cibuildwheel's `before-all`, so a
plain sdist build would otherwise tarball an empty
`src/pycoraza/coreruleset/rules/` directory. End users who `pip install`
from sdist would then get a wheel with no CRS rules, breaking the CRS
profile helpers at runtime.

This hook calls the same CRS fetch logic the wheel build runs (see
`native/scripts/build-libcoraza.sh:fetch_crs`), so the produced
sdist contains the rule tree the wheel build would have populated.

Wheel-side concerns (libcoraza build, cffi compile) live in
`native/build_ffi.py` so all wheel hooks fire from one custom-hook
declaration.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # pragma: no cover - hatch not present in dev installs
    BuildHookInterface = object  # type: ignore[assignment,misc]


REPO_ROOT = Path(__file__).resolve().parent
RULES_DIR = REPO_ROOT / "src" / "pycoraza" / "coreruleset" / "rules"
VERSION_FILE = REPO_ROOT / "native" / "version.txt"


def _crs_already_fetched() -> bool:
    """True if the CRS rule tree on disk looks complete enough to ship."""
    if not RULES_DIR.is_dir():
        return False
    inner = RULES_DIR / "rules"
    if not inner.is_dir():
        return False
    return any(inner.glob("REQUEST-*.conf"))


def _fetch_crs() -> None:
    """Mirror `fetch_crs` from `native/scripts/build-libcoraza.sh`.

    Re-implemented inline rather than `bash -c "source ...; fetch_crs"`
    because sourcing the script triggers its top-level `main "$@"` which
    runs the full Go install + libcoraza build. We only want the CRS
    download here.
    """
    if not VERSION_FILE.is_file():
        raise RuntimeError(f"version manifest missing at {VERSION_FILE}")
    script = f"""
set -euo pipefail
source "{VERSION_FILE}"
rules_dir="{RULES_DIR}"
if [[ -f "${{rules_dir}}/.crs-tag" ]] \\
    && [[ "$(cat "${{rules_dir}}/.crs-tag")" == "${{CRS_TAG}}" ]]; then
  echo "CRS ${{CRS_TAG}} already present at ${{rules_dir}}"
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


class CrsFetchHook(BuildHookInterface):
    """Sdist build hook: fetch OWASP CRS rules before packaging.

    Runs at the start of `python -m build --sdist`. Idempotent — short-
    circuits when the CRS tag stamped under
    `src/pycoraza/coreruleset/rules/.crs-tag` matches the pinned
    `CRS_TAG` in `native/version.txt`.
    """

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if _crs_already_fetched():
            return
        _fetch_crs()


if __name__ == "__main__":  # pragma: no cover - manual debugging only
    _fetch_crs()
