"""Integration smoke — requires a real libcoraza build.

Skipped automatically when only the in-memory fake bindings are present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _has_native() -> bool:
    pkg_root = Path(__file__).resolve().parents[2] / "src" / "pycoraza" / "_bindings"
    if not pkg_root.is_dir():
        return False
    return any(pkg_root.glob("_pycoraza*.so")) or any(pkg_root.glob("_pycoraza*.pyd"))


if not _has_native():
    pytest.skip(
        "libcoraza native extension not built; run ./native/scripts/build-libcoraza.sh",
        allow_module_level=True,
    )


class TestRealLib:
    def test_create_and_close(self) -> None:
        from pycoraza import WAFConfig, create_waf

        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n"))
        assert waf.rules_count() >= 0
        waf.close()

    def test_transaction_happy_path(self) -> None:
        from pycoraza import ProcessMode, RequestInfo, WAFConfig, create_waf

        waf = create_waf(
            WAFConfig(rules="SecRuleEngine On\n", mode=ProcessMode.DETECT)
        )
        try:
            with waf.new_transaction() as tx:
                tx.process_connection("127.0.0.1", 54321)
                interrupted = tx.process_request_bundle(
                    RequestInfo(method="GET", url="/", headers=())
                )
                assert interrupted in (True, False)
        finally:
            waf.close()

    def test_blocking_rule(self) -> None:
        from pycoraza import ProcessMode, RequestInfo, WAFConfig, create_waf

        # `log` + `severity` are required for coraza to invoke the
        # error callback. Custom rules without these fire `deny` but
        # silently from the operator's POV. CRS rules always set them.
        rules = (
            "SecRuleEngine On\n"
            'SecRule REQUEST_URI "@contains /attack" '
            '"id:100001,phase:1,deny,status:403,log,severity:\'WARNING\','
            "msg:'attack hit'\"\n"
        )
        waf = create_waf(WAFConfig(rules=rules, mode=ProcessMode.BLOCK))
        try:
            with waf.new_transaction() as tx:
                tx.process_connection("127.0.0.1", 10)
                interrupted = tx.process_request_bundle(
                    RequestInfo(method="GET", url="/attack?x=1", headers=())
                )
                assert interrupted is True
                intr = tx.interruption()
                assert intr is not None
                assert intr.status == 403
                # Real rule id (not 0) flows through the error callback.
                assert intr.rule_id == 100001
                # And the matched chain is exposed.
                matches = tx.matched_rules()
                assert len(matches) >= 1
                assert any(m.id == 100001 for m in matches)
        finally:
            waf.close()


class TestMatchedRulesCRS:
    """End-to-end check that a SQLi attack against CRS exposes 942xxx ids.

    This is the regression that proves operators actually see WHICH rule
    fired on a CRS block — without this, `Interruption.rule_id` was always
    0 and triage required re-running in detect mode.
    """

    def test_crs_sqli_block_exposes_rule_chain(self) -> None:
        from pycoraza import ProcessMode, RequestInfo, WAFConfig, create_waf
        from pycoraza.coreruleset import recommended

        rules = "SecRuleEngine On\n" + recommended(paranoia=1)
        waf = create_waf(WAFConfig(rules=rules, mode=ProcessMode.BLOCK))
        try:
            with waf.new_transaction() as tx:
                tx.process_connection("198.51.100.10", 12345)
                interrupted = tx.process_request_bundle(
                    RequestInfo(
                        method="GET",
                        url="/?id=1' OR '1'='1",
                        headers=(("host", "example.test"),
                                 ("user-agent", "pytest-integration/0.1")),
                    )
                )
                assert interrupted is True, "CRS must block this SQLi"
                intr = tx.interruption()
                assert intr is not None
                # Disruptive rule id is no longer hard-coded 0.
                assert intr.rule_id != 0, (
                    f"Interruption.rule_id should be populated; got {intr!r}"
                )
                matches = tx.matched_rules()
                assert len(matches) > 0, "matched_rules() must surface the chain"
                # CRS SQLi rules live in the 942xxx family.
                ids = [m.id for m in matches]
                assert any(942000 <= i <= 942999 for i in ids), (
                    f"expected a 942xxx SQLi rule in the chain, got {ids}"
                )
                # Print for visibility — `pytest -v` will show this.
                print(f"\n[CRS-SQLi] disruptive rule_id={intr.rule_id} chain={ids}")
        finally:
            waf.close()
