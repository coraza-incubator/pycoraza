"""CRS profile helpers.

Builds SecLang directive strings that load OWASP CRS rule files.
Rule `.conf` files ship under `pycoraza/coreruleset/rules/`; see
`native/scripts/build-libcoraza.sh` for how they are fetched.
"""

from ._profiles import (
    CrsCategory,
    CrsOptions,
    ParanoiaLevel,
    PYTHON_WEB_INCLUDES,
    balanced,
    permissive,
    python_web,
    recommended,
    strict,
)

__all__ = [
    "CrsCategory",
    "CrsOptions",
    "ParanoiaLevel",
    "PYTHON_WEB_INCLUDES",
    "balanced",
    "permissive",
    "python_web",
    "recommended",
    "strict",
]
