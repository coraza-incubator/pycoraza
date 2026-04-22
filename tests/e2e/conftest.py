"""E2E tests against real libcoraza + real HTTP servers.

Each adapter fixture boots the corresponding example app in a
subprocess with `PYCORAZA_WAF=on` and `PYCORAZA_MODE=block`, waits on
`/healthz`, yields the base URL, then kills the process group on
teardown.

Skipped as a suite if:
  * The compiled `pycoraza._bindings._pycoraza.*.so` extension is not
    on disk (integration suite guard).
  * The corresponding framework (flask / starlette / fastapi) isn't
    importable.
  * `gunicorn` / `uvicorn` binaries aren't on PATH.

Marker: `e2e` — matches `pyproject.toml [tool.pytest.ini_options].markers`.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIBCORAZA_PREFIX = os.environ.get(
    "LIBCORAZA_PREFIX", str(REPO_ROOT / "build" / "libcoraza")
)


def _native_extension_present() -> bool:
    pkg_root = REPO_ROOT / "src" / "pycoraza" / "_bindings"
    if not pkg_root.is_dir():
        return False
    return any(pkg_root.glob("_pycoraza*.so")) or any(pkg_root.glob("_pycoraza*.pyd"))


def _find_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_healthy(url: str, timeout: float = 30.0) -> None:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code < 500:
                return
        except (httpx.HTTPError, OSError):
            pass
        time.sleep(0.2)
    raise RuntimeError(f"server not healthy at {url} within {timeout}s")


def _start_server(cmd: list[str], env_extra: dict[str, str]) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(env_extra)
    env["PYTHONPATH"] = f"{REPO_ROOT / 'src'}:{REPO_ROOT / 'examples' / 'shared'}"
    env["LD_LIBRARY_PATH"] = f"{LIBCORAZA_PREFIX}/lib:{env.get('LD_LIBRARY_PATH', '')}"
    return subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(REPO_ROOT),
        start_new_session=True,
    )


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


if not _native_extension_present():
    pytest.skip(
        "libcoraza native extension not built; run ./native/scripts/build-libcoraza.sh",
        allow_module_level=True,
    )


pytest.importorskip("httpx")


@pytest.fixture(scope="module")
def flask_url() -> Iterator[str]:
    pytest.importorskip("flask")
    if not shutil.which("gunicorn") and not (Path(sys.executable).parent / "gunicorn").exists():
        pytest.skip("gunicorn not installed")
    port = _find_port()
    proc = _start_server(
        [
            sys.executable, "-m", "gunicorn",
            "--workers", "1", "--worker-class", "sync",
            "-b", f"127.0.0.1:{port}",
            "--chdir", str(REPO_ROOT / "examples" / "flask_app"),
            "--access-logfile", "/dev/null", "--error-logfile", "/dev/null",
            "app:app",
        ],
        env_extra={
            "PYCORAZA_PORT": str(port),
            "PYCORAZA_WAF": "on",
            "PYCORAZA_MODE": "block",
        },
    )
    try:
        _wait_healthy(f"http://127.0.0.1:{port}/healthz")
        yield f"http://127.0.0.1:{port}"
    finally:
        _stop(proc)


@pytest.fixture(scope="module")
def starlette_url() -> Iterator[str]:
    pytest.importorskip("starlette")
    pytest.importorskip("uvicorn")
    port = _find_port()
    proc = _start_server(
        [
            sys.executable, "-m", "uvicorn",
            "--app-dir", str(REPO_ROOT / "examples" / "starlette_app"),
            "--workers", "1",
            "--log-level", "warning", "--no-access-log",
            "--host", "127.0.0.1", "--port", str(port),
            "app:app",
        ],
        env_extra={
            "PYCORAZA_PORT": str(port),
            "PYCORAZA_WAF": "on",
            "PYCORAZA_MODE": "block",
        },
    )
    try:
        _wait_healthy(f"http://127.0.0.1:{port}/healthz")
        yield f"http://127.0.0.1:{port}"
    finally:
        _stop(proc)


@pytest.fixture(scope="module")
def fastapi_url() -> Iterator[str]:
    pytest.importorskip("fastapi")
    pytest.importorskip("uvicorn")
    port = _find_port()
    proc = _start_server(
        [
            sys.executable, "-m", "uvicorn",
            "--app-dir", str(REPO_ROOT / "examples" / "fastapi_app"),
            "--workers", "1",
            "--log-level", "warning", "--no-access-log",
            "--host", "127.0.0.1", "--port", str(port),
            "app:app",
        ],
        env_extra={
            "PYCORAZA_PORT": str(port),
            "PYCORAZA_WAF": "on",
            "PYCORAZA_MODE": "block",
        },
    )
    try:
        _wait_healthy(f"http://127.0.0.1:{port}/healthz")
        yield f"http://127.0.0.1:{port}"
    finally:
        _stop(proc)
