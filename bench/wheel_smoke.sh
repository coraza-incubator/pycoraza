#!/usr/bin/env bash
# Wheel smoke driver — installs the published-wheel into a fresh venv and
# verifies each adapter boots and applies CRS the same way real users get
# it via `pip install pycoraza`.
#
# This is the developer-runnable mirror of `.github/workflows/wheel-smoke.yml`.
# The workflow calls THIS script after building libcoraza + a wheel, so any
# fix you make here is the fix CI ships.
#
# Usage:
#   bash bench/wheel_smoke.sh /path/to/pycoraza-*.whl
#
# Required env (the CI workflow exports these — for local runs, set them):
#   LIBCORAZA_PREFIX  — path to a libcoraza tree containing lib/libcoraza.so.
#                       The compiled cffi inside the wheel was linked against
#                       libcoraza but the wheel does NOT bundle it (no
#                       auditwheel-repair step in the smoke build), so the
#                       loader needs LD_LIBRARY_PATH at runtime.
#
# Optional env:
#   PYTHON      — interpreter used to seed the smoke venv (default: python3).
#   SMOKE_VENV  — venv path (default: /tmp/pycoraza-smoke-venv).
#   ADAPTERS    — space-separated subset of {flask fastapi starlette}
#                 (default: all three).
#
# Exit codes:
#   0   every probe matched the expected status across every adapter.
#   2   bad usage.
#   3   adapter failed to come up within the boot grace.
#   4   probe matrix mismatch (clear "want NNN got MMM" message printed).

set -euo pipefail

WHEEL="${1:-}"
if [[ -z "${WHEEL}" || ! -f "${WHEEL}" ]]; then
  echo "usage: bash bench/wheel_smoke.sh <path-to-wheel>" >&2
  exit 2
fi
WHEEL="$(readlink -f "${WHEEL}")"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
SMOKE_VENV="${SMOKE_VENV:-/tmp/pycoraza-smoke-venv}"
ADAPTERS="${ADAPTERS:-flask fastapi starlette}"

if [[ -z "${LIBCORAZA_PREFIX:-}" || ! -d "${LIBCORAZA_PREFIX}/lib" ]]; then
  echo "LIBCORAZA_PREFIX must point to a tree with lib/libcoraza.so;" >&2
  echo "got: '${LIBCORAZA_PREFIX:-<unset>}'" >&2
  exit 2
fi

echo "==> Wheel:           ${WHEEL}"
echo "==> LIBCORAZA_PREFIX: ${LIBCORAZA_PREFIX}"
echo "==> Smoke venv:      ${SMOKE_VENV}"
echo "==> Adapters:        ${ADAPTERS}"

# Fresh venv every run — never reuse, the whole point is to catch
# packaging regressions a stale workspace would mask.
rm -rf "${SMOKE_VENV}"
"${PYTHON}" -m venv "${SMOKE_VENV}"
SMOKE_PY="${SMOKE_VENV}/bin/python"
SMOKE_PIP="${SMOKE_VENV}/bin/pip"

"${SMOKE_PIP}" install --upgrade pip >/dev/null
echo "==> Installing wheel + framework extras + harness deps"
"${SMOKE_PIP}" install -q "${WHEEL}[flask,fastapi,starlette]"
"${SMOKE_PIP}" install -q gunicorn 'uvicorn[standard]' httpx

# Sanity: the cffi extension can resolve libcoraza.so. If this import
# fails we want a loud, early signal instead of a confusing boot error.
LD_LIBRARY_PATH="${LIBCORAZA_PREFIX}/lib:${LD_LIBRARY_PATH:-}" \
  "${SMOKE_PY}" -c "import pycoraza; waf = pycoraza.create_waf(pycoraza.WAFConfig(rules='SecRuleEngine On')); print(f'pycoraza import ok, rules_count={waf.rules_count()}')"

# Probe matrix. Status per row: GET healthz must return 200, the benign
# /search must return 200 (CRS at paranoia=1 must not flag a normal
# query with sane headers), the two attacks must be 403 in block mode.
# /echo with SQLi-in-body is recorded as "200 or 403" because whether
# CRS sees the body depends on whether the example app surfaces it as
# an inspected variable — we accept both rather than over-asserting.

probe_one() {
  # Args: label method url want_status [body_json]
  local label="$1" method="$2" url="$3" want="$4" body="${5:-}"
  local got
  if [[ -n "${body}" ]]; then
    got=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H 'User-Agent: pycoraza-wheel-smoke/1.0' \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      -X "${method}" --data "${body}" "${url}")
  else
    got=$(curl -sS -o /dev/null -w "%{http_code}" \
      -H 'User-Agent: pycoraza-wheel-smoke/1.0' \
      -H 'Accept: application/json' \
      -X "${method}" "${url}")
  fi
  case "${want}" in
    *"|"*)
      if [[ "|${want}|" != *"|${got}|"* ]]; then
        echo "  FAIL ${label}: want one of [${want}] got ${got}" >&2
        return 4
      fi
      ;;
    *)
      if [[ "${got}" != "${want}" ]]; then
        echo "  FAIL ${label}: want ${want} got ${got}" >&2
        return 4
      fi
      ;;
  esac
  printf "  OK   %-22s %s -> %s\n" "${label}" "${url}" "${got}"
  return 0
}

# CRS at paranoia=1 with sensible probe headers should be quiet on
# benign traffic and loud on the two classic XSS/SQLi shapes.
run_probes() {
  local port="$1" fw="$2"
  local base="http://127.0.0.1:${port}"
  local rc=0
  probe_one "healthz"        GET  "${base}/healthz"                                                  200 || rc=$?
  probe_one "search benign"  GET  "${base}/search?q=hello"                                           200 || rc=$?
  probe_one "search XSS"     GET  "${base}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"               403 || rc=$?
  probe_one "echo SQLi-body" POST "${base}/echo"                                                     "200|403" '{"q":"1'"'"' OR '"'"'1'"'"'='"'"'1"}' || rc=$?
  probe_one "search SQLi"    GET  "${base}/search?q=1+UNION+SELECT+NULL"                             403 || rc=$?
  return ${rc}
}

# Wait until /healthz answers 200 or give up. We accept any 2xx from a
# plain GET (server is alive) — the /healthz status assertion happens
# in the probe matrix itself.
wait_for_boot() {
  local port="$1" fw="$2" log="$3"
  for i in $(seq 1 80); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "ERROR: ${fw} on :${port} never answered /healthz" >&2
  echo "------ tail of ${log} ------" >&2
  tail -50 "${log}" >&2 || true
  return 3
}

boot_and_probe() {
  local fw="$1"
  local port server_cmd log
  case "${fw}" in
    flask)
      port=5101
      # gunicorn matches the bench + FTW path real users follow.
      server_cmd="${SMOKE_VENV}/bin/gunicorn --workers 2 --worker-class sync \
        -b 127.0.0.1:${port} \
        --chdir ${ROOT}/examples/flask_app \
        --access-logfile /dev/null --error-logfile - app:app"
      ;;
    fastapi)
      port=5102
      server_cmd="${SMOKE_PY} -m uvicorn \
        --app-dir ${ROOT}/examples/fastapi_app \
        --workers 1 --log-level warning --no-access-log \
        --host 127.0.0.1 --port ${port} app:app"
      ;;
    starlette)
      port=5103
      server_cmd="${SMOKE_PY} -m uvicorn \
        --app-dir ${ROOT}/examples/starlette_app \
        --workers 1 --log-level warning --no-access-log \
        --host 127.0.0.1 --port ${port} app:app"
      ;;
    *)
      echo "unknown adapter '${fw}'" >&2
      return 2
      ;;
  esac

  log="/tmp/pycoraza-smoke-${fw}.log"
  : > "${log}"

  # Block-mode CRS, regular routing (FTW=0). We want the standard route
  # matrix from the example apps, not the FTW catch-all echo.
  echo
  echo "==> Booting ${fw} on :${port}"
  setsid env \
    PATH="${SMOKE_VENV}/bin:${PATH}" \
    LD_LIBRARY_PATH="${LIBCORAZA_PREFIX}/lib:${LD_LIBRARY_PATH:-}" \
    PYCORAZA_WAF=on \
    PYCORAZA_MODE=block \
    PYCORAZA_PORT="${port}" \
    FTW=0 \
    bash -c "${server_cmd}" >"${log}" 2>&1 &
  local server_pid=$!

  # Always tear the server down, even on probe failure.
  cleanup() {
    kill -- "-${server_pid}" 2>/dev/null || true
    sleep 0.3
    kill -9 -- "-${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  }
  trap cleanup RETURN

  wait_for_boot "${port}" "${fw}" "${log}"

  local rc=0
  run_probes "${port}" "${fw}" || rc=$?
  cleanup
  trap - RETURN
  return ${rc}
}

overall=0
for fw in ${ADAPTERS}; do
  if ! boot_and_probe "${fw}"; then
    echo "==> ${fw}: PROBE MATRIX FAILED" >&2
    overall=4
  else
    echo "==> ${fw}: ok"
  fi
done

if [[ ${overall} -ne 0 ]]; then
  echo
  echo "WHEEL SMOKE FAILED — wheel under test: ${WHEEL}" >&2
  exit ${overall}
fi
echo
echo "WHEEL SMOKE PASSED — wheel under test: ${WHEEL}"
