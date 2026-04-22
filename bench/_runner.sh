#!/usr/bin/env bash
# Bench driver. For each (framework, mode): start the app, wait for healthz,
# run wrk against 4 routes that actually hit the WAF (not skipped by the
# static-asset filter), kill the server, record RPS + p50/p90/p99.
#
# Usage: bash bench/_runner.sh <framework> <waf_mode>
#   framework: flask | fastapi | starlette
#   waf_mode:  off | detect | block
#
# Output: bench/results/<framework>-<waf_mode>.txt

set -euo pipefail

FW="${1:?framework required}"
MODE="${2:?mode required: off|detect|block}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="${ROOT}/bench/results"
mkdir -p "${RESULTS}"

PYTHON="${PYTHON:-python3}"
GUNICORN="${GUNICORN:-gunicorn}"
DURATION="${DURATION:-15s}"
CONNS="${CONNS:-50}"
WORKERS="${WORKERS:-4}"

case "$FW" in
  flask)     PORT=5000; SERVER="${GUNICORN} --workers ${WORKERS} --worker-class sync -b 127.0.0.1:${PORT} --chdir ${ROOT}/examples/flask_app --access-logfile /dev/null --error-logfile - app:app" ;;
  fastapi)   PORT=5001; SERVER="${PYTHON} -m uvicorn --app-dir ${ROOT}/examples/fastapi_app --workers ${WORKERS} --log-level warning --no-access-log --host 127.0.0.1 --port ${PORT} app:app" ;;
  starlette) PORT=5002; SERVER="${PYTHON} -m uvicorn --app-dir ${ROOT}/examples/starlette_app --workers ${WORKERS} --log-level warning --no-access-log --host 127.0.0.1 --port ${PORT} app:app" ;;
  *) echo "unknown framework $FW" >&2; exit 2 ;;
esac

export LD_LIBRARY_PATH="${ROOT}/build/libcoraza/lib"
export PYTHONPATH="${ROOT}/src"
export PYCORAZA_PORT="${PORT}"
case "$MODE" in
  off)    export PYCORAZA_WAF=off; unset PYCORAZA_MODE ;;
  detect) export PYCORAZA_WAF=on;  export PYCORAZA_MODE=detect ;;
  block)  export PYCORAZA_WAF=on;  export PYCORAZA_MODE=block ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac

OUT="${RESULTS}/${FW}-${MODE}.txt"
: > "${OUT}"
{
  echo "=== ${FW} waf=${MODE} (python=${PYTHON##*/}, workers=${WORKERS}, duration=${DURATION}, conns=${CONNS}) ==="
} | tee -a "${OUT}"

setsid bash -c "${SERVER}" >/tmp/bench-${FW}-${MODE}.log 2>&1 &
SERVER_PID=$!
trap "kill -- -${SERVER_PID} 2>/dev/null || true; sleep 0.3; kill -9 -- -${SERVER_PID} 2>/dev/null || true" EXIT

for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.3
  if [[ $i -eq 40 ]]; then
    echo "server never came up" >&2
    tail -20 /tmp/bench-${FW}-${MODE}.log
    exit 3
  fi
done

# Post-boot sanity: if WAF should be on, attack must return 403 in block mode
# and WAF should at least be evaluating (benign 200) in detect.
if [[ "$MODE" == "block" ]]; then
  attack_status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
  echo "  block-check XSS: ${attack_status}" | tee -a "${OUT}"
fi

run_wrk() {
  local label="$1"; local path="$2"
  local out
  out=$(wrk -t2 -c"${CONNS}" -d"${DURATION}" --latency "http://127.0.0.1:${PORT}${path}" 2>&1)
  local rps p50 p90 p99
  rps=$(echo "$out" | awk '/Requests\/sec:/{print $2}')
  p50=$(echo "$out" | awk '/ 50%/{print $2}')
  p90=$(echo "$out" | awk '/ 90%/{print $2}')
  p99=$(echo "$out" | awk '/ 99%/{print $2}')
  printf "  %-22s RPS=%-10s p50=%-8s p90=%-8s p99=%-8s\n" "$label" "$rps" "$p50" "$p90" "$p99" | tee -a "${OUT}"
}

# Only routes that actually reach the WAF (no static-asset bypass).
run_wrk "GET /"             "/"
run_wrk "GET /healthz"      "/healthz"
run_wrk "GET /search?q=..." "/search?q=hello+world"
run_wrk "GET /api/users/42" "/api/users/42"

kill -- -${SERVER_PID} 2>/dev/null || true
sleep 0.3
kill -9 -- -${SERVER_PID} 2>/dev/null || true
wait ${SERVER_PID} 2>/dev/null || true
