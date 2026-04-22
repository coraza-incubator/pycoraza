"""SecLang profile helpers — parallel to `@coraza/coreruleset`.

Design rule: **files we won't use are never referenced**. Profiles emit
`Include` directives for an explicit whitelist of rule files only.
There is no "include everything then filter by language tag" path —
that still costs a directory scan and could surface a file we never
vetted.

When CRS ships new rule families, they stay dark until an explicit
change adds them to the appropriate whitelist. That is intentional:
new rule families change perf and false-positive profiles, and those
shifts should be visible in source control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import as_file, files
from pathlib import Path
from typing import Literal

ParanoiaLevel = Literal[1, 2, 3, 4]

CrsCategory = Literal[
    "901", "905", "911", "913", "920", "921", "922", "930", "931",
    "932", "933", "934", "941", "942", "943", "944", "949",
    "950", "951", "952", "953", "954", "955", "959", "980",
]


@dataclass(slots=True)
class CrsOptions:
    """Tuning knobs shared across every profile."""

    paranoia: ParanoiaLevel = 1
    inbound_anomaly_threshold: int = 5
    outbound_anomaly_threshold: int = 4
    anomaly_block: bool = True
    exclude_categories: tuple[CrsCategory, ...] = field(default_factory=tuple)
    extra: str = ""


_DEFAULT_PROFILE = CrsOptions()


# Rule files we evaluate for Python web apps. Anything not listed here
# is NEVER loaded into libcoraza — the engine cannot scan against a
# rule that was never compiled in. Whitelist discipline is deliberate:
# a CRS bump cannot silently add new rule work to the hot path.
#
# Dropped relative to upstream CRS v4.11:
#   REQUEST-931 (RFI)         — mostly a PHP-class bug
#   REQUEST-933 (PHP)         — PHP engine targets only
#   REQUEST-934 (GENERIC)     — Node.js prototype pollution / template-injection
#   RESPONSE-953 (PHP)
#   RESPONSE-954 (IIS)
# REQUEST-944-JAVA stays: Python apps commonly proxy to Java microservices.
PYTHON_WEB_INCLUDES: tuple[str, ...] = (
    "REQUEST-901-INITIALIZATION.conf",
    "REQUEST-905-COMMON-EXCEPTIONS.conf",
    "REQUEST-911-METHOD-ENFORCEMENT.conf",
    "REQUEST-913-SCANNER-DETECTION.conf",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    "REQUEST-921-PROTOCOL-ATTACK.conf",
    "REQUEST-922-MULTIPART-ATTACK.conf",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
    "REQUEST-949-BLOCKING-EVALUATION.conf",
    "REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
    "RESPONSE-950-DATA-LEAKAGES.conf",
    "RESPONSE-951-DATA-LEAKAGES-SQL.conf",
    "RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
    "RESPONSE-955-WEB-SHELLS.conf",
    "RESPONSE-959-BLOCKING-EVALUATION.conf",
    "RESPONSE-980-CORRELATION.conf",
)


def _rules_dir() -> Path:
    """Return the on-disk path to the bundled CRS rules directory.

    Uses `importlib.resources` so it works from a wheel and from an
    editable install. `as_file` gives us a filesystem path libcoraza
    can open via `coraza_rules_add_file`.
    """
    base = files("pycoraza.coreruleset").joinpath("rules")
    with as_file(base) as p:
        return Path(p)


def _include(path: Path) -> str:
    return f"Include {path.as_posix()}"


def _profile_actions(opts: CrsOptions) -> list[str]:
    actions = [
        f'SecAction "id:900000,phase:1,nolog,pass,t:none,'
        f'setvar:tx.blocking_paranoia_level={opts.paranoia}"',
        f'SecAction "id:900001,phase:1,nolog,pass,t:none,'
        f'setvar:tx.inbound_anomaly_score_threshold={opts.inbound_anomaly_threshold}"',
        f'SecAction "id:900002,phase:1,nolog,pass,t:none,'
        f'setvar:tx.outbound_anomaly_score_threshold={opts.outbound_anomaly_threshold}"',
    ]
    if not opts.anomaly_block:
        actions.append(
            'SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:tx.anomaly_block=0"'
        )
    return actions


def _category_excluded(filename: str, excluded: tuple[CrsCategory, ...]) -> bool:
    for cat in excluded:
        if filename.startswith(f"REQUEST-{cat}-") or filename.startswith(f"RESPONSE-{cat}-"):
            return True
    return False


def _whitelist_includes(
    whitelist: tuple[str, ...], opts: CrsOptions, base: Path
) -> list[str]:
    rules = base / "rules"
    if not rules.is_dir():
        return []
    out: list[str] = []
    for name in whitelist:
        if _category_excluded(name, opts.exclude_categories):
            continue
        conf = rules / name
        if conf.is_file():
            out.append(_include(conf))
    return out


def _build(whitelist: tuple[str, ...], opts: CrsOptions) -> str:
    base = _rules_dir()
    setup = base / "crs-setup.conf.example"

    lines: list[str] = []
    if setup.is_file():
        lines.append(_include(setup))
    lines.extend(_profile_actions(opts))
    lines.extend(_whitelist_includes(whitelist, opts, base))
    if opts.extra:
        lines.append(opts.extra)
    return "\n".join(lines) + "\n"


def python_web(
    paranoia: ParanoiaLevel = 1,
    *,
    inbound_anomaly_threshold: int = _DEFAULT_PROFILE.inbound_anomaly_threshold,
    outbound_anomaly_threshold: int = _DEFAULT_PROFILE.outbound_anomaly_threshold,
    anomaly_block: bool = True,
    exclude_categories: tuple[CrsCategory, ...] = (),
    extra: str = "",
) -> str:
    """Python-scoped CRS preset. Loads only `PYTHON_WEB_INCLUDES`.

    Paranoia 1 with standard anomaly thresholds. Keep this as the
    default for Flask/FastAPI/Starlette deployments unless you have
    a concrete reason to load more rule families.
    """
    opts = CrsOptions(
        paranoia=paranoia,
        inbound_anomaly_threshold=inbound_anomaly_threshold,
        outbound_anomaly_threshold=outbound_anomaly_threshold,
        anomaly_block=anomaly_block,
        exclude_categories=exclude_categories,
        extra=extra,
    )
    return _build(PYTHON_WEB_INCLUDES, opts)


def recommended(
    paranoia: ParanoiaLevel = 1,
    *,
    inbound_anomaly_threshold: int = _DEFAULT_PROFILE.inbound_anomaly_threshold,
    outbound_anomaly_threshold: int = _DEFAULT_PROFILE.outbound_anomaly_threshold,
    anomaly_block: bool = True,
    exclude_categories: tuple[CrsCategory, ...] = (),
    extra: str = "",
) -> str:
    """Default preset — alias for `python_web()`.

    pycoraza targets Python web servers, so the "general" preset and
    the "Python-scoped" preset are the same whitelist. Kept under the
    `recommended` name for API parity with coraza-node.
    """
    return python_web(
        paranoia=paranoia,
        inbound_anomaly_threshold=inbound_anomaly_threshold,
        outbound_anomaly_threshold=outbound_anomaly_threshold,
        anomaly_block=anomaly_block,
        exclude_categories=exclude_categories,
        extra=extra,
    )


def balanced(**overrides: object) -> str:
    """Paranoia 2, same whitelist, stricter defaults."""
    kwargs: dict[str, object] = {
        "paranoia": 2,
        "inbound_anomaly_threshold": 5,
        "outbound_anomaly_threshold": 4,
    }
    kwargs.update(overrides)
    return recommended(**kwargs)  # type: ignore[arg-type]


def strict(**overrides: object) -> str:
    """Paranoia 3, tight thresholds — expect false positives."""
    kwargs: dict[str, object] = {
        "paranoia": 3,
        "inbound_anomaly_threshold": 3,
        "outbound_anomaly_threshold": 3,
    }
    kwargs.update(overrides)
    return recommended(**kwargs)  # type: ignore[arg-type]


def permissive(**overrides: object) -> str:
    """Paranoia 1, loose thresholds — logs most things, blocks little."""
    kwargs: dict[str, object] = {
        "paranoia": 1,
        "inbound_anomaly_threshold": 10,
        "outbound_anomaly_threshold": 8,
        "anomaly_block": False,
    }
    kwargs.update(overrides)
    return recommended(**kwargs)  # type: ignore[arg-type]


__all__ = [
    "PYTHON_WEB_INCLUDES",
    "CrsCategory",
    "CrsOptions",
    "ParanoiaLevel",
    "balanced",
    "permissive",
    "python_web",
    "recommended",
    "strict",
]
