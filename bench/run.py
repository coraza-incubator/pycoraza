"""Per-route benchmark runner: drives `wrk` against each canonical route.

Mirrors `coraza-node/bench/run.ts`. For a single adapter it boots the
example app once (with `PYCORAZA_WAF` flipped), waits for `/healthz`,
then shells out to `wrk` per route. Parses wrk's stdout for Requests/sec
and latency percentiles and prints a markdown table.

Usage:
    python bench/run.py --framework flask
    python bench/run.py --framework fastapi --duration 15 --connections 100
    python bench/run.py --framework starlette --waf off --json out.json

Prereqs:
    - `wrk` on PATH (brew install wrk / apt install wrk).
    - Example app for the chosen framework runnable via
      `python examples/<fw>_app/app.py` — respects `PYCORAZA_PORT` and
      `PYCORAZA_WAF` env vars.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FRAMEWORKS: dict[str, dict[str, object]] = {
    "flask": {"port": 8001, "module": "examples/flask_app/app.py"},
    "fastapi": {"port": 8002, "module": "examples/fastapi_app/app.py"},
    "starlette": {"port": 8003, "module": "examples/starlette_app/app.py"},
}

# The canonical 7 routes. Matches examples/shared/pycoraza_shared.py.
# `body` / `content_type` only set for POST routes.
ROUTES: list[dict[str, str | None]] = [
    {"label": "GET /", "method": "GET", "path": "/", "body": None, "content_type": None},
    {"label": "GET /healthz", "method": "GET", "path": "/healthz", "body": None, "content_type": None},
    {"label": "GET /search", "method": "GET", "path": "/search?q=hello+world", "body": None, "content_type": None},
    {"label": "POST /echo", "method": "POST", "path": "/echo", "body": '{"msg":"hi"}', "content_type": "application/json"},
    {"label": "POST /upload", "method": "POST", "path": "/upload", "body": "x" * 1024, "content_type": "application/octet-stream"},
    {"label": "GET /img/logo.png", "method": "GET", "path": "/img/logo.png", "body": None, "content_type": None},
    {"label": "GET /api/users/42", "method": "GET", "path": "/api/users/42", "body": None, "content_type": None},
]


@dataclass(slots=True)
class RouteResult:
    label: str
    method: str
    path: str
    rps: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    avg_ms: float
    max_ms: float
    socket_errors: int = 0
    non_2xx: int = 0
    raw: str = field(default="", repr=False)


@dataclass(slots=True)
class RunReport:
    framework: str
    waf: str
    duration: int
    connections: int
    threads: int
    port: int
    routes: list[RouteResult] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Per-route wrk benchmark against a pycoraza example app.",
    )
    p.add_argument("--framework", choices=sorted(FRAMEWORKS), required=True)
    p.add_argument("--waf", choices=("on", "off"), default="on",
                   help="Toggle PYCORAZA_WAF env var (default: on).")
    p.add_argument("--duration", type=int, default=10, help="Seconds per route.")
    p.add_argument("--connections", type=int, default=50)
    p.add_argument("--threads", type=int, default=2)
    p.add_argument("--port", type=int, default=None,
                   help="Override the default per-framework port.")
    p.add_argument("--warmup", type=float, default=1.0,
                   help="Seconds to idle after /healthz responds before benching.")
    p.add_argument("--json", dest="json_out", type=Path, default=None,
                   help="Also dump machine-readable JSON to this path.")
    p.add_argument("--no-table", action="store_true",
                   help="Skip the markdown table on stdout.")
    return p.parse_args()


def require_wrk() -> str:
    path = shutil.which("wrk")
    if not path:
        sys.stderr.write(
            "error: `wrk` not found on PATH.\n"
            "  install via `brew install wrk` (macOS) or `apt install wrk` (debian/ubuntu).\n",
        )
        sys.exit(2)
    return path


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def boot_app(framework: str, port: int, waf_on: bool) -> subprocess.Popen[bytes]:
    cfg = FRAMEWORKS[framework]
    module = ROOT / str(cfg["module"])
    if not module.exists():
        sys.stderr.write(f"error: example app not found at {module}\n")
        sys.exit(2)
    env = os.environ.copy()
    env["PYCORAZA_PORT"] = str(port)
    env["PYCORAZA_WAF"] = "on" if waf_on else "off"
    # Keep the app's own logging out of the way — benchmark results go to stdout.
    env.setdefault("PYTHONUNBUFFERED", "1")
    return subprocess.Popen(
        [sys.executable, str(module)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_for_health(port: int, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    url = f"http://127.0.0.1:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            pass
        time.sleep(0.2)
    raise TimeoutError(f"server on :{port} did not come up within {timeout_s:.0f}s")


def shutdown(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


_LATENCY_LINE = re.compile(
    r"^\s*Latency\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)",
)
_RPS_LINE = re.compile(r"^\s*Requests/sec:\s+([\d.]+)")
_PCTL_LINE = re.compile(r"^\s*(\d{2})%\s+([\d.]+)(us|ms|s)")
_SOCK_ERRS = re.compile(
    r"^\s*Socket errors: connect \d+, read \d+, write \d+, timeout (\d+)",
)
_NON2XX = re.compile(r"^\s*Non-2xx or 3xx responses:\s+(\d+)")


def _to_ms(value: str, unit: str) -> float:
    v = float(value)
    if unit == "us":
        return v / 1000.0
    if unit == "s":
        return v * 1000.0
    return v


def parse_wrk(output: str) -> tuple[float, float, float, float, float, float, int, int]:
    """Return (rps, avg_ms, max_ms, p50_ms, p95_ms, p99_ms, sock_err, non_2xx)."""
    rps = 0.0
    avg_ms = 0.0
    max_ms = 0.0
    pctl: dict[int, float] = {}
    sock_err = 0
    non_2xx = 0
    for line in output.splitlines():
        m = _RPS_LINE.match(line)
        if m:
            rps = float(m.group(1))
            continue
        m = _LATENCY_LINE.match(line)
        if m:
            avg_ms = _to_ms(m.group(1), m.group(2))
            max_ms = _to_ms(m.group(5), m.group(6))
            continue
        m = _PCTL_LINE.match(line)
        if m:
            pct = int(m.group(1))
            pctl[pct] = _to_ms(m.group(2), m.group(3))
            continue
        m = _SOCK_ERRS.match(line)
        if m:
            sock_err = int(m.group(1))
            continue
        m = _NON2XX.match(line)
        if m:
            non_2xx = int(m.group(1))
    return (
        rps,
        avg_ms,
        max_ms,
        pctl.get(50, 0.0),
        pctl.get(95, 0.0),
        pctl.get(99, 0.0),
        sock_err,
        non_2xx,
    )


def run_wrk(
    wrk_bin: str,
    url: str,
    method: str,
    body: str | None,
    content_type: str | None,
    connections: int,
    threads: int,
    duration: int,
) -> str:
    cmd = [
        wrk_bin,
        "-t", str(threads),
        "-c", str(connections),
        "-d", f"{duration}s",
        "--latency",
    ]
    if method.upper() != "GET" or body is not None:
        cmd += ["-s", _write_script(method, body or "", content_type)]
    cmd.append(url)
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        sys.stderr.write(f"wrk failed for {url}: exit {res.returncode}\n{res.stderr}\n")
    return res.stdout


_SCRIPT_CACHE: dict[tuple[str, str, str | None], str] = {}


def _write_script(method: str, body: str, content_type: str | None) -> str:
    key = (method.upper(), body, content_type)
    cached = _SCRIPT_CACHE.get(key)
    if cached is not None:
        return cached
    lua_lines = [f'wrk.method = "{method.upper()}"']
    if body:
        escaped = body.replace("\\", "\\\\").replace('"', '\\"')
        lua_lines.append(f'wrk.body = "{escaped}"')
    if content_type:
        lua_lines.append(f'wrk.headers["Content-Type"] = "{content_type}"')
    script = "\n".join(lua_lines) + "\n"
    tmp = Path("/tmp") / f"pycoraza-wrk-{abs(hash(key))}.lua"
    tmp.write_text(script, encoding="utf-8")
    _SCRIPT_CACHE[key] = str(tmp)
    return str(tmp)


def run_all_routes(
    wrk_bin: str,
    port: int,
    args: argparse.Namespace,
) -> list[RouteResult]:
    results: list[RouteResult] = []
    for spec in ROUTES:
        url = f"http://127.0.0.1:{port}{spec['path']}"
        stdout = run_wrk(
            wrk_bin,
            url,
            str(spec["method"]),
            spec["body"],  # type: ignore[arg-type]
            spec["content_type"],  # type: ignore[arg-type]
            args.connections,
            args.threads,
            args.duration,
        )
        rps, avg_ms, max_ms, p50, p95, p99, sock_err, non_2xx = parse_wrk(stdout)
        r = RouteResult(
            label=str(spec["label"]),
            method=str(spec["method"]),
            path=str(spec["path"]),
            rps=rps,
            avg_ms=avg_ms,
            max_ms=max_ms,
            p50_ms=p50,
            p95_ms=p95,
            p99_ms=p99,
            socket_errors=sock_err,
            non_2xx=non_2xx,
            raw=stdout,
        )
        results.append(r)
        sys.stderr.write(
            f"  {spec['label']}: rps={rps:,.0f} p50={p50:.2f}ms p99={p99:.2f}ms\n",
        )
    return results


def render_markdown(report: RunReport) -> str:
    header = (
        f"## pycoraza bench ({report.framework}, WAF={report.waf})\n\n"
        f"duration={report.duration}s connections={report.connections} "
        f"threads={report.threads} port={report.port}\n\n"
    )
    rows = ["| Route | RPS | p50 | p95 | p99 | non-2xx |",
            "|---|---:|---:|---:|---:|---:|"]
    for r in report.routes:
        rows.append(
            f"| {r.label} | {r.rps:,.0f} | {r.p50_ms:.2f}ms | "
            f"{r.p95_ms:.2f}ms | {r.p99_ms:.2f}ms | {r.non_2xx} |",
        )
    return header + "\n".join(rows) + "\n"


def report_to_json(report: RunReport) -> dict[str, object]:
    d = asdict(report)
    for route in d["routes"]:
        route.pop("raw", None)
    return d


def main() -> int:
    args = parse_args()
    wrk_bin = require_wrk()
    cfg = FRAMEWORKS[args.framework]
    port = args.port or int(cfg["port"])  # type: ignore[arg-type]

    if not port_is_free(port):
        sys.stderr.write(
            f"error: port {port} already in use. Pass --port <N> or free it.\n",
        )
        return 2

    waf_on = args.waf == "on"
    sys.stderr.write(
        f"-- booting {args.framework} on :{port} PYCORAZA_WAF={args.waf}\n",
    )
    proc = boot_app(args.framework, port, waf_on)
    try:
        try:
            wait_for_health(port)
        except TimeoutError as e:
            shutdown(proc)
            tail = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            sys.stderr.write(f"{e}\n--- app stderr tail ---\n{tail}\n")
            return 1
        time.sleep(args.warmup)
        results = run_all_routes(wrk_bin, port, args)
    finally:
        shutdown(proc)

    report = RunReport(
        framework=args.framework,
        waf=args.waf,
        duration=args.duration,
        connections=args.connections,
        threads=args.threads,
        port=port,
        routes=results,
    )

    if not args.no_table:
        sys.stdout.write(render_markdown(report))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report_to_json(report), indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
