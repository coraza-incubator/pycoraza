"""`pycoraza.coreruleset` SecLang profile builders."""

from __future__ import annotations

from pathlib import Path

import pytest

from pycoraza.coreruleset import (
    PYTHON_WEB_INCLUDES,
    CrsOptions,
    _profiles,
    balanced,
    permissive,
    python_web,
    recommended,
    strict,
)


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

    def test_does_not_glob_rules_dir(self, fake_rules_dir: Path) -> None:
        (fake_rules_dir / "rules" / "REQUEST-999-CUSTOM.conf").write_text("# custom")
        out = recommended()
        assert "REQUEST-999-CUSTOM.conf" not in out


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
        assert opts.anomaly_block is True
        assert opts.exclude_categories == ()


class TestPythonWeb:
    def test_whitelist_is_nonempty(self) -> None:
        assert len(PYTHON_WEB_INCLUDES) >= 15
        for name in PYTHON_WEB_INCLUDES:
            assert name.endswith(".conf")
            assert name.startswith(("REQUEST-", "RESPONSE-"))

    def test_drops_rfi_generic_php_iis(self, fake_rules_dir: Path) -> None:
        (fake_rules_dir / "rules" / "REQUEST-931-APPLICATION-ATTACK-RFI.conf").write_text("# rfi")
        (fake_rules_dir / "rules" / "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf").write_text("# generic")
        (fake_rules_dir / "rules" / "RESPONSE-954-DATA-LEAKAGES-IIS.conf").write_text("# iis")

        out = python_web()
        assert "REQUEST-931-APPLICATION-ATTACK-RFI.conf" not in out
        assert "REQUEST-933-APPLICATION-ATTACK-PHP.conf" not in out
        assert "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf" not in out
        assert "RESPONSE-953-DATA-LEAKAGES-PHP.conf" not in out
        assert "RESPONSE-954-DATA-LEAKAGES-IIS.conf" not in out

    def test_keeps_xss_sqli_lfi(self, fake_rules_dir: Path) -> None:
        out = python_web()
        assert "REQUEST-941-APPLICATION-ATTACK-XSS.conf" in out
        assert "REQUEST-901-INITIALIZATION.conf" in out

    def test_honors_paranoia(self, fake_rules_dir: Path) -> None:
        out = python_web(paranoia=3)
        assert "tx.blocking_paranoia_level=3" in out

    def test_honors_exclude_categories(self, fake_rules_dir: Path) -> None:
        (fake_rules_dir / "rules" / "REQUEST-920-PROTOCOL-ENFORCEMENT.conf").write_text("# proto")
        out_default = python_web()
        assert "REQUEST-920-PROTOCOL-ENFORCEMENT.conf" in out_default

        out_excluded = python_web(exclude_categories=("920",))
        assert "REQUEST-920-PROTOCOL-ENFORCEMENT.conf" not in out_excluded

    def test_extra_appended(self, fake_rules_dir: Path) -> None:
        out = python_web(extra='SecRule REQUEST_URI "@contains /admin" "id:9999,deny"')
        assert 'id:9999,deny' in out


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
