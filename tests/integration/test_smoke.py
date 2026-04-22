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

        rules = (
            "SecRuleEngine On\n"
            'SecRule REQUEST_URI "@contains /attack" '
            '"id:100001,phase:1,deny,status:403"\n'
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
        finally:
            waf.close()
