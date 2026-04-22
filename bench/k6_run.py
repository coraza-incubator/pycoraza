"""k6-based mixed-traffic benchmark runner.

Mirrors `coraza-node/bench/k6-run.ts`. Boots the selected example app,
runs `k6 run --summary-export=<tmp> bench/k6/mixed.js`, parses the
summary JSON, prints a markdown summary and exits non-zero if the
script recorded any missed attacks (a hard-fail signal — a missed
attack means a WAF regression, not a perf blip).

Usage:
    python bench/k6_run.py --framework flask
    python bench/k6_run.py --framework fastapi --vus 100 --duration 30s
    python bench/k6_run.py --framework starlette --json out.json

Prereqs:
    - `k6` on PATH (https://k6.io/docs/get-started/installation/).
    - Example app runnable via `python examples/<fw>_app/app.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
K6_SCRIPT = ROOT / "bench" / "k6" / "mixed.js"

FRAMEWORKS: dict[str, dict[str, object]] = {
    "flask": {"port": 8001, "module": "examples/flask_app/app.py"},
    "fastapi": {"port": 8002, "module": "examples/fastapi_app/app.py"},
    "starlette": {"port": 8003, "module": "examples/starlette_app/app.py"},
}


@dataclass(slots=True)
class K6Summary:
    framework: str
    waf: str
    vus: int
    duration: str
    total_requests: int
    rps: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    avg_ms: float
    blocked_attacks: int
    missed_attacks: int
    checks_rate: float
    raw: dict[str, object] = field(default_factory=dict, repr=False)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="k6 mixed-traffic benchmark for pycoraza adapters.",
    )
    p.add_argument("--framework", choices=sorted(FRAMEWORKS), required=True)
    p.add_argument("--waf", choices=("on", "off"), default="on")
    p.add_argument("--vus", type=int, default=50)
    p.add_argument("--duration", default="20s", help="e.g. 20s, 1m.")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--warmup", type=float, default=2.0)
    p.add_argument("--json", dest="json_out", type=Path, default=None)
    return p.parse_args()


def require_k6() -> str:
    path = shutil.which("k6")
    if not path:
        sys.stderr.write(
            "error: `k6` not found on PATH.\n"
            "  install per https://k6.io/docs/get-started/installation/\n",
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


def run_k6(k6_bin: str, port: int, args: argparse.Namespace) -> dict[str, object]:
    if not K6_SCRIPT.exists():
        sys.stderr.write(f"error: k6 script missing at {K6_SCRIPT}\n")
        sys.exit(2)
    with tempfile.NamedTemporaryFile(
        prefix="pycoraza-k6-", suffix=".json", delete=False,
    ) as tmp:
        summary_path = Path(tmp.name)

    env = os.environ.copy()
    env["TARGET_URL"] = f"http://127.0.0.1:{port}"
    env["BASE_URL"] = env["TARGET_URL"]  # alias for coraza-node compatibility
    env["VUS"] = str(args.vus)
    env["DURATION"] = args.duration

    cmd = [
        k6_bin, "run",
        "--summary-export", str(summary_path),
        str(K6_SCRIPT),
    ]
    res = subprocess.run(cmd, env=env, check=False)
    # k6 exits 99 when thresholds fail but the run still produced data.
    if res.returncode not in (0, 99):
        sys.stderr.write(f"k6 exited with code {res.returncode}\n")
        sys.exit(res.returncode)
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    finally:
        try:
            summary_path.unlink()
        except OSError:
            pass
    return data


def _metric_value(raw: dict[str, object], name: str, key: str, default: float = 0.0) -> float:
    metrics = raw.get("metrics")
    if not isinstance(metrics, dict):
        return default
    m = metrics.get(name)
    if not isinstance(m, dict):
        return default
    v = m.get(key)
    if v is None:
        return default
    try:
        return float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def summarize(
    raw: dict[str, object],
    framework: str,
    waf: str,
    vus: int,
    duration: str,
) -> K6Summary:
    return K6Summary(
        framework=framework,
        waf=waf,
        vus=vus,
        duration=duration,
        total_requests=int(_metric_value(raw, "http_reqs", "count")),
        rps=_metric_value(raw, "http_reqs", "rate"),
        avg_ms=_metric_value(raw, "http_req_duration", "avg"),
        p50_ms=_metric_value(raw, "http_req_duration", "med"),
        p95_ms=_metric_value(raw, "http_req_duration", "p(95)"),
        p99_ms=_metric_value(raw, "http_req_duration", "p(99)"),
        blocked_attacks=int(_metric_value(raw, "blocked_attacks", "count")),
        missed_attacks=int(_metric_value(raw, "missed_attacks", "count")),
        checks_rate=_metric_value(raw, "checks", "rate", default=1.0),
        raw=raw,
    )


def render_markdown(s: K6Summary) -> str:
    lines = [
        f"## pycoraza k6 mixed ({s.framework}, WAF={s.waf})",
        "",
        f"vus={s.vus} duration={s.duration} total_requests={s.total_requests:,}",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Requests/sec | {s.rps:,.1f} |",
        f"| avg latency | {s.avg_ms:.2f} ms |",
        f"| p50 latency | {s.p50_ms:.2f} ms |",
        f"| p95 latency | {s.p95_ms:.2f} ms |",
        f"| p99 latency | {s.p99_ms:.2f} ms |",
        f"| blocked attacks | {s.blocked_attacks} |",
        f"| missed attacks | {s.missed_attacks} |",
        f"| checks pass rate | {s.checks_rate * 100:.2f}% |",
        "",
    ]
    return "\n".join(lines)


def summary_to_json(s: K6Summary) -> dict[str, object]:
    d = asdict(s)
    d.pop("raw", None)
    return d


def main() -> int:
    args = parse_args()
    k6_bin = require_k6()
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
        raw = run_k6(k6_bin, port, args)
    finally:
        shutdown(proc)

    summary = summarize(raw, args.framework, args.waf, args.vus, args.duration)
    sys.stdout.write(render_markdown(summary))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(summary_to_json(summary), indent=2) + "\n",
            encoding="utf-8",
        )

    if waf_on and summary.missed_attacks > 0:
        sys.stderr.write(
            f"\nFAIL: {summary.missed_attacks} attack payload(s) returned 2xx.\n"
            "This is a WAF regression — investigate before landing.\n",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
