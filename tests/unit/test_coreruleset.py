"""`pycoraza.coreruleset` SecLang profile builders."""

from __future__ import annotations

from pathlib import Path

import pytest

from pycoraza.coreruleset import (
    CrsOptions,
    balanced,
    permissive,
    recommended,
    strict,
)
from pycoraza.coreruleset import _profiles


@pytest.fixture
def fake_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "crs"
    rules = base / "rules"
    rules.mkdir(parents=True)
    (base / "crs-setup.conf.example").write_text("# setup")
    (rules / "REQUEST-901-INITIALIZATION.conf").write_text("# 901")
    (rules / "REQUEST-913-SCANNER-DETECTION.conf").write_text("# 913")
    (rules / "REQUEST-933-APPLICATION-ATTACK-PHP.conf").write_text("# php")
    (rules / "REQUEST-941-APPLICATION-ATTACK-XSS.conf").write_text("# xss")
    (rules / "RESPONSE-950-DATA-LEAKAGES.conf").write_text("# leak")
    (rules / "RESPONSE-953-DATA-LEAKAGES-PHP.conf").write_text("# php leak")

    monkeypatch.setattr(_profiles, "_rules_dir", lambda: base)
    return base


class TestRecommended:
    def test_emits_include_directives(self, fake_rules_dir: Path) -> None:
        out = recommended()
        assert f"Include {fake_rules_dir}/crs-setup.conf.example" in out
        assert "REQUEST-901-INITIALIZATION.conf" in out
        assert "REQUEST-941-APPLICATION-ATTACK-XSS.conf" in out

    def test_excludes_php_by_default(self, fake_rules_dir: Path) -> None:
        out = recommended()
        assert "REQUEST-933-APPLICATION-ATTACK-PHP.conf" not in out
        assert "RESPONSE-953-DATA-LEAKAGES-PHP.conf" not in out

    def test_emits_anomaly_thresholds(self, fake_rules_dir: Path) -> None:
        out = recommended(paranoia=2, inbound_anomaly_threshold=7)
        assert "tx.blocking_paranoia_level=2" in out
        assert "tx.inbound_anomaly_score_threshold=7" in out

    def test_anomaly_block_false_emits_directive(self, fake_rules_dir: Path) -> None:
        out = recommended(anomaly_block=False)
        assert "tx.anomaly_block=0" in out

    def test_exclude_categories(self, fake_rules_dir: Path) -> None:
        out = recommended(exclude_categories=("941",))
        assert "REQUEST-941-APPLICATION-ATTACK-XSS.conf" not in out
        assert "REQUEST-901-INITIALIZATION.conf" in out

    def test_extra_appended(self, fake_rules_dir: Path) -> None:
        out = recommended(extra="SecRuleRemoveById 942100")
        assert out.strip().endswith("SecRuleRemoveById 942100")

    def test_include_php_when_not_excluded(self, fake_rules_dir: Path) -> None:
        out = recommended(exclude=(), outbound_exclude=())
        assert "REQUEST-933-APPLICATION-ATTACK-PHP.conf" in out
        assert "RESPONSE-953-DATA-LEAKAGES-PHP.conf" in out


class TestBalanced:
    def test_paranoia_defaults_to_2(self, fake_rules_dir: Path) -> None:
        out = balanced()
        assert "tx.blocking_paranoia_level=2" in out


class TestStrict:
    def test_paranoia_defaults_to_3(self, fake_rules_dir: Path) -> None:
        out = strict()
        assert "tx.blocking_paranoia_level=3" in out
        assert "tx.inbound_anomaly_score_threshold=3" in out


class TestPermissive:
    def test_disables_anomaly_block(self, fake_rules_dir: Path) -> None:
        out = permissive()
        assert "tx.anomaly_block=0" in out


class TestCrsOptions:
    def test_defaults(self) -> None:
        opts = CrsOptions()
        assert opts.paranoia == 1
        assert "php" in opts.exclude
        assert opts.anomaly_block is True
        assert opts.exclude_categories == ()


class TestMissingRulesDir:
    def test_missing_dir_produces_actions_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setattr(_profiles, "_rules_dir", lambda: empty)
        out = recommended()
        assert "tx.blocking_paranoia_level=1" in out
        assert "Include " not in out
