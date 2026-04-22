#!/usr/bin/env bash
# Sanity: make sure the BLOCK mode actually blocks known attack payloads
# (otherwise "waf=block" numbers would be misleading).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LD_LIBRARY_PATH="${ROOT}/build/libcoraza/lib"
export PYTHONPATH="${ROOT}/src"

PYTHON="${PYTHON:-python3}"
GUNICORN="${GUNICORN:-gunicorn}"

for fw in flask fastapi starlette; do
  case "$fw" in
    flask)     PORT=5000; CMD="${GUNICORN} --workers 2 --worker-class sync -b 127.0.0.1:${PORT} --chdir ${ROOT}/examples/flask_app --access-logfile /dev/null --error-logfile /dev/null app:app" ;;
    fastapi)   PORT=5001; CMD="${PYTHON} -m uvicorn --app-dir ${ROOT}/examples/fastapi_app --workers 2 --log-level warning --no-access-log --host 127.0.0.1 --port ${PORT} app:app" ;;
    starlette) PORT=5002; CMD="${PYTHON} -m uvicorn --app-dir ${ROOT}/examples/starlette_app --workers 2 --log-level warning --no-access-log --host 127.0.0.1 --port ${PORT} app:app" ;;
  esac

  export PYCORAZA_PORT="${PORT}"
  export PYCORAZA_WAF=on
  export FTW=1

  setsid bash -c "${CMD}" >/tmp/verify-${fw}.log 2>&1 &
  PID=$!
  trap "kill -- -${PID} 2>/dev/null || true; kill -9 -- -${PID} 2>/dev/null || true" EXIT

  for i in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
    sleep 0.3
  done

  # Known CRS-triggering payloads
  attacks=(
    "sqli:/?id=1+UNION+SELECT+NULL,NULL,NULL--"
    "xss:/?q=%3Cscript%3Ealert(1)%3C/script%3E"
    "traversal:/?f=../../../../etc/passwd"
  )
  echo "=== ${fw} block check ==="
  for entry in "${attacks[@]}"; do
    label="${entry%%:*}"; path="${entry#*:}"
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}${path}")
    printf "  %-12s %s\n" "${label}" "${status}"
  done

  kill -- -${PID} 2>/dev/null || true
  sleep 0.5
  kill -9 -- -${PID} 2>/dev/null || true
  wait ${PID} 2>/dev/null || true
  trap - EXIT
  unset FTW
  sleep 1
done
