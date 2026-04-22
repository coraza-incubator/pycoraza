"""SecLang profile helpers — parallel to `@coraza/coreruleset`.

These emitters produce a string of SecLang directives that:
  * Include the CRS setup file.
  * Tune per-profile SecAction IDs (paranoia, anomaly thresholds).
  * Include the full CRS rule corpus.

They assume the CRS rule files are bundled under
`src/pycoraza/coreruleset/rules/` (fetched at build time by
`native/scripts/build-libcoraza.sh`). `recommended()` and friends
return absolute `Include <path>` directives that libcoraza's
`coraza_rules_add` accepts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import as_file, files
from pathlib import Path
from typing import Literal

LanguageTag = Literal[
    "php", "java", "dotnet", "nodejs", "iis", "generic"
]

ParanoiaLevel = Literal[1, 2, 3, 4]

CrsCategory = Literal[
    "901", "905", "911", "913", "920", "921", "922", "930", "931",
    "932", "933", "934", "941", "942", "943", "944", "949",
    "950", "951", "952", "953", "954", "955", "959", "980",
]


@dataclass(slots=True)
class CrsOptions:
    """Tuning knobs for a CRS profile. Mirrors coraza-node's `CrsOptions`."""

    paranoia: ParanoiaLevel = 1
    exclude: tuple[LanguageTag, ...] = ("php", "java", "dotnet")
    outbound_exclude: tuple[LanguageTag, ...] = ("php", "java", "dotnet")
    inbound_anomaly_threshold: int = 5
    outbound_anomaly_threshold: int = 4
    anomaly_block: bool = True
    exclude_categories: tuple[CrsCategory, ...] = field(default_factory=tuple)
    extra: str = ""


_DEFAULT_PROFILE = CrsOptions()


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


def _language_excluded(filename: str, excluded: tuple[LanguageTag, ...]) -> bool:
    lowered = filename.lower()
    for tag in excluded:
        if f"-{tag}-" in lowered or lowered.endswith(f"-{tag}.conf"):
            return True
    return False


def _category_excluded(filename: str, excluded: tuple[CrsCategory, ...]) -> bool:
    for cat in excluded:
        if filename.startswith(f"REQUEST-{cat}-") or filename.startswith(f"RESPONSE-{cat}-"):
            return True
    return False


def _crs_includes(opts: CrsOptions, base: Path) -> list[str]:
    rules = base / "rules"
    if not rules.is_dir():
        return []
    out: list[str] = []
    for conf in sorted(rules.glob("*.conf")):
        name = conf.name
        if name.startswith("RESPONSE-"):
            if _language_excluded(name, opts.outbound_exclude):
                continue
        elif _language_excluded(name, opts.exclude):
            continue
        if _category_excluded(name, opts.exclude_categories):
            continue
        out.append(_include(conf))
    return out


def _build(opts: CrsOptions) -> str:
    base = _rules_dir()
    setup = base / "crs-setup.conf.example"

    lines: list[str] = []
    if setup.is_file():
        lines.append(_include(setup))
    lines.extend(_profile_actions(opts))
    lines.extend(_crs_includes(opts, base))
    if opts.extra:
        lines.append(opts.extra)
    return "\n".join(lines) + "\n"


def recommended(
    paranoia: ParanoiaLevel = 1,
    *,
    exclude: tuple[LanguageTag, ...] = _DEFAULT_PROFILE.exclude,
    outbound_exclude: tuple[LanguageTag, ...] = _DEFAULT_PROFILE.outbound_exclude,
    inbound_anomaly_threshold: int = _DEFAULT_PROFILE.inbound_anomaly_threshold,
    outbound_anomaly_threshold: int = _DEFAULT_PROFILE.outbound_anomaly_threshold,
    anomaly_block: bool = True,
    exclude_categories: tuple[CrsCategory, ...] = (),
    extra: str = "",
) -> str:
    """Balanced defaults suitable for most deployments."""
    return _build(CrsOptions(
        paranoia=paranoia,
        exclude=exclude,
        outbound_exclude=outbound_exclude,
        inbound_anomaly_threshold=inbound_anomaly_threshold,
        outbound_anomaly_threshold=outbound_anomaly_threshold,
        anomaly_block=anomaly_block,
        exclude_categories=exclude_categories,
        extra=extra,
    ))


def balanced(**overrides: object) -> str:
    """Alias for `recommended` with paranoia=2, stricter thresholds."""
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
    "CrsCategory",
    "CrsOptions",
    "LanguageTag",
    "ParanoiaLevel",
    "balanced",
    "permissive",
    "recommended",
    "strict",
]
