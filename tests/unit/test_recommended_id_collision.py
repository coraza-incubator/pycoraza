"""coraza-node #30: warn on rule-id collisions in `extra=` SecLang.

`recommended()` and `python_web()` concatenate `extra=` after the four
`SecAction id:90000{0,1,2,3}` directives the helper emits. SecLang is
last-write-wins, so a user `id:900001` silently shadows the inbound
anomaly threshold with no engine-level error.

We flag collisions on:

* the four helper-emitted ids (900000-900003)
* the broader CRS-reserved range (900000-999999)

Note: `pyproject.toml` has `filterwarnings=['error']`, so plain
`warnings.warn` would be promoted to error. Tests use
`pytest.warns(UserWarning)` to capture the warning cleanly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pycoraza.coreruleset import _profiles, python_web, recommended


@pytest.fixture
def fake_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "crs"
    rules = base / "rules"
    rules.mkdir(parents=True)
    (base / "crs-setup.conf.example").write_text("# setup")
    (rules / "REQUEST-901-INITIALIZATION.conf").write_text("# 901")
    monkeypatch.setattr(_profiles, "_rules_dir", lambda: base)
    return base


class TestHelperEmittedIds:
    def test_warns_on_helper_id_900001(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"900001"):
            recommended(extra='SecAction "id:900001,phase:1,nolog,pass"')

    def test_warns_on_helper_id_900000(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"900000"):
            recommended(extra='SecAction "id:900000,phase:1,nolog,pass"')

    def test_warns_on_helper_id_900002(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"900002"):
            recommended(extra='SecAction "id:900002,phase:1,nolog,pass"')

    def test_warns_on_helper_id_900003(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"900003"):
            recommended(extra='SecAction "id:900003,phase:1,nolog,pass"')


class TestCrsReservedRange:
    def test_warns_on_crs_range_id_920100(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"920100"):
            recommended(extra='SecAction "id:920100,phase:1,nolog,pass"')

    def test_warns_on_crs_range_id_949999(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"949999"):
            recommended(extra='SecAction "id:949999,phase:1,nolog,pass"')

    def test_warns_on_crs_range_upper_boundary_999999(
        self, fake_rules_dir: Path
    ) -> None:
        with pytest.warns(UserWarning, match=r"999999"):
            recommended(extra='SecAction "id:999999,phase:1,nolog,pass"')


class TestSafeIds:
    def test_no_warning_below_reserved_range(self, fake_rules_dir: Path) -> None:
        # warnings.error filter from pyproject.toml will surface any
        # stray warning as a test failure.
        recommended(extra='SecAction "id:1000001,phase:1,nolog,pass"')

    def test_no_warning_for_user_id_9999(self, fake_rules_dir: Path) -> None:
        recommended(extra='SecRule REQUEST_URI "@contains /admin" "id:9999,deny"')

    def test_no_warning_for_id_899999(self, fake_rules_dir: Path) -> None:
        # 899999 is just below the CRS reserved range (900000-999999)
        recommended(extra='SecAction "id:899999,phase:1,nolog,pass"')

    def test_no_warning_for_id_1000000(self, fake_rules_dir: Path) -> None:
        # 1000000 is just above the CRS reserved range
        recommended(extra='SecAction "id:1000000,phase:1,nolog,pass"')

    def test_no_warning_when_extra_empty(self, fake_rules_dir: Path) -> None:
        recommended()  # default extra=""

    def test_no_warning_for_secruleremovebyid_942100(
        self, fake_rules_dir: Path
    ) -> None:
        # `SecRuleRemoveById 942100` does NOT use the `id:NNN` token
        # syntax — it's a directive arg, not an `id:` action. Should
        # not trigger the regex.
        recommended(extra="SecRuleRemoveById 942100")


class TestPythonWebPath:
    """Same checks via `python_web()` since `recommended` is just an alias."""

    def test_warns_via_python_web(self, fake_rules_dir: Path) -> None:
        with pytest.warns(UserWarning, match=r"900001"):
            python_web(extra='SecAction "id:900001,phase:1,nolog,pass"')

    def test_no_warning_via_python_web(self, fake_rules_dir: Path) -> None:
        python_web(extra='SecAction "id:1000042,phase:1,nolog,pass"')


class TestMultipleCollisions:
    def test_warns_once_with_all_ids(self, fake_rules_dir: Path) -> None:
        extra = (
            'SecAction "id:900001,phase:1,nolog,pass"\n'
            'SecAction "id:920500,phase:1,nolog,pass"\n'
        )
        with pytest.warns(UserWarning) as record:
            recommended(extra=extra)
        assert len(record) == 1
        msg = str(record[0].message)
        assert "900001" in msg
        assert "920500" in msg

    def test_dedups_repeated_id(self, fake_rules_dir: Path) -> None:
        extra = (
            'SecAction "id:900001,phase:1,nolog,pass"\n'
            'SecAction "id:900001,phase:1,nolog,pass"\n'
        )
        with pytest.warns(UserWarning) as record:
            recommended(extra=extra)
        msg = str(record[0].message)
        assert msg.count("900001") == 1
