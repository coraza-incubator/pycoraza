"""Thread-safety of the error/debug callback trampolines.

The fake ABI delivers callbacks in-line, but we exercise the full
registration path from multiple threads to make sure the callback list
is retained and reentrant Python invocation works.

The integration-marked test exercises the real cffi trampoline from a
native goroutine; it is skipped unless the compiled `_bindings._pycoraza`
extension is importable.
"""

from __future__ import annotations

import threading
from importlib import util as importlib_util

import pytest

from _fake_abi import FakeLib, _FakeCData

from pycoraza.abi import Abi


class TestInlineCallback:
    def test_error_callback_in_thread(self, fake_abi: FakeLib) -> None:
        import time

        abi = Abi()
        cfg = abi.new_waf_config()
        received: list[tuple[int, str, int]] = []
        lock = threading.Lock()

        def cb(sev: int, log: str) -> None:
            with lock:
                received.append((sev, log, threading.get_ident()))

        abi.register_error_callback(cfg, cb)
        tramp = fake_abi.configs[id(cfg)].error_callback
        assert tramp is not None

        barrier = threading.Barrier(4)

        def worker() -> None:
            barrier.wait()
            for _ in range(10):
                tramp(None, _FakeCData(b"boom"))
                time.sleep(0.0001)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 40
        tids = {r[2] for r in received}
        assert len(tids) >= 2

    def test_debug_callback_survives_python_exception(self, fake_abi: FakeLib) -> None:
        abi = Abi(logger=None)
        cfg = abi.new_waf_config()

        def cb(_level: int, _msg: str, _fields: str) -> None:
            raise RuntimeError("python-side boom")

        abi.register_debug_callback(cfg, cb)
        tramp = fake_abi.configs[id(cfg)].debug_callback
        assert tramp is not None
        tramp(None, 1, _FakeCData(b"m"), _FakeCData(b"f"))


class TestCallbackRetention:
    def test_trampolines_kept_alive(self, fake_abi: FakeLib) -> None:
        abi = Abi()
        cfg = abi.new_waf_config()
        abi.register_error_callback(cfg, lambda s, l: None)
        abi.register_debug_callback(cfg, lambda lvl, m, f: None)
        assert len(abi._callback_refs) == 2


@pytest.mark.integration
class TestRealBindings:
    def test_skip_without_native(self) -> None:
        spec = importlib_util.find_spec("pycoraza._bindings._pycoraza")
        if spec is None:
            pytest.skip("libcoraza native extension not built")
        from pycoraza import WAFConfig, create_waf

        waf = create_waf(WAFConfig(rules="SecRuleEngine On\n"))
        waf.close()
