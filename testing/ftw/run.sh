#!/usr/bin/env bash
# testing/ftw/run.sh — drive the OWASP CRS regression corpus (via
# coreruleset/go-ftw) against one of our FTW-mode example adapters.
#
# Modelled on coraza-node/testing/ftw/run.sh, adapted for pycoraza:
#
#   * Target is a Python/WSGI (Flask) or ASGI (FastAPI / Starlette)
#     process booted in-band; no Docker.
#   * CRS corpus + go-ftw versions are pinned in native/version.txt so the
#     tests always match the rules compiled into the native .so and so
#     reruns are reproducible.
#
# Usage:
#   bash testing/ftw/run.sh --framework=flask
#   bash testing/ftw/run.sh --framework=fastapi --port=5001
#   bash testing/ftw/run.sh --framework=starlette --threshold=95
#   bash testing/ftw/run.sh --framework=flask --crs-tag=v4.11.0
#
# Environment knobs (normally unset locally):
#   GO_FTW_VERSION   pinned go-ftw tag (else read from native/version.txt).
#   CRS_TAG          force a specific corpus tag (else from version.txt).
#   SKIP_BOOT=1      don't boot the example — assume something already bound
#                    on PORT (useful for debugging).
#   BOOT_TIMEOUT     seconds to wait for the adapter's port to answer
#                    (default 60).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/testing/ftw/build"
CRS_CACHE="${BUILD_DIR}/crs"

FRAMEWORK=""
PORT=""
THRESHOLD="100"
CRS_TAG_ARG=""
GO_FTW_VERSION_ARG=""
SKIP_BOOT="${SKIP_BOOT:-0}"

# ---- Argument parsing -----------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --framework=*)       FRAMEWORK="${1#*=}"; shift ;;
    --framework)         FRAMEWORK="$2"; shift 2 ;;
    --port=*)            PORT="${1#*=}"; shift ;;
    --port)              PORT="$2"; shift 2 ;;
    --threshold=*)       THRESHOLD="${1#*=}"; shift ;;
    --threshold)         THRESHOLD="$2"; shift 2 ;;
    --crs-tag=*)         CRS_TAG_ARG="${1#*=}"; shift ;;
    --crs-tag)           CRS_TAG_ARG="$2"; shift 2 ;;
    --go-ftw-version=*)  GO_FTW_VERSION_ARG="${1#*=}"; shift ;;
    --go-ftw-version)    GO_FTW_VERSION_ARG="$2"; shift 2 ;;
    --skip-boot)         SKIP_BOOT=1; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${FRAMEWORK}" ]]; then
  echo "--framework=<flask|fastapi|starlette> is required" >&2
  exit 2
fi

case "${FRAMEWORK}" in
  flask)     DEFAULT_PORT=5000 ;;
  fastapi)   DEFAULT_PORT=5001 ;;
  starlette) DEFAULT_PORT=5002 ;;
  django)    DEFAULT_PORT=5003 ;;
  *) echo "unknown framework: ${FRAMEWORK} (flask|fastapi|starlette|django)" >&2; exit 2 ;;
esac
PORT="${PORT:-${DEFAULT_PORT}}"

# ---- 1. Source pinned versions from native/version.txt --------------
VERSION_FILE="${REPO_ROOT}/native/version.txt"
if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "missing ${VERSION_FILE}" >&2
  exit 1
fi

read_version_key() {
  awk -F= -v k="$1" '$1 == k { print $2 }' "${VERSION_FILE}"
}

CRS_TAG="${CRS_TAG_ARG:-${CRS_TAG:-$(read_version_key CRS_TAG)}}"
GO_FTW_VERSION="${GO_FTW_VERSION_ARG:-${GO_FTW_VERSION:-$(read_version_key GO_FTW_VERSION)}}"

if [[ -z "${CRS_TAG}" ]]; then
  echo "could not resolve CRS_TAG (no --crs-tag, no env, no native/version.txt entry)" >&2
  exit 1
fi
if [[ -z "${GO_FTW_VERSION}" ]]; then
  echo "could not resolve GO_FTW_VERSION" >&2
  exit 1
fi

crs_version="${CRS_TAG#v}"
echo "[ftw] framework=${FRAMEWORK} port=${PORT} crs=v${crs_version} go-ftw=${GO_FTW_VERSION}"

# ---- 2. Install go-ftw (pinned) -------------------------------------
# Use `go install` so we get a binary at $GOBIN/go-ftw — avoids a
# module-mode `go run` round-trip per invocation.
mkdir -p "${BUILD_DIR}"
INSTALL_DIR="${BUILD_DIR}/gobin"
mkdir -p "${INSTALL_DIR}"
export GOBIN="${INSTALL_DIR}"
if [[ ! -x "${GOBIN}/go-ftw" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "[ftw] 'go' not in PATH; cannot install go-ftw@${GO_FTW_VERSION}." >&2
    exit 1
  fi
  echo "[ftw] Installing go-ftw@${GO_FTW_VERSION}..."
  # go-ftw follows semantic import versioning — v2+ takes the /v2 suffix.
  GO111MODULE=on go install "github.com/coreruleset/go-ftw/v2@${GO_FTW_VERSION}"
fi
FTW_BIN="${GOBIN}/go-ftw"

# ---- 3. Fetch & cache the CRS corpus at the pinned tag --------------
mkdir -p "${CRS_CACHE}"
CRS_CHECKOUT="${CRS_CACHE}/v${crs_version}"
if [[ ! -d "${CRS_CHECKOUT}" ]]; then
  echo "[ftw] Fetching coreruleset v${crs_version}..."
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" EXIT
  curl -fsSL \
    "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${crs_version}.tar.gz" \
    -o "${tmp}/crs.tar.gz"
  mkdir -p "${CRS_CHECKOUT}"
  tar -xzf "${tmp}/crs.tar.gz" -C "${CRS_CHECKOUT}" --strip-components=1
  rm -rf "${tmp}"
  trap - EXIT
fi
CRS_TESTS_DIR="${CRS_CHECKOUT}/tests/regression/tests"
[[ -d "${CRS_TESTS_DIR}" ]] || { echo "missing tests dir: ${CRS_TESTS_DIR}" >&2; exit 1; }
corpus_size="$(find "${CRS_TESTS_DIR}" -name '*.yaml' | wc -l | tr -d ' ')"
echo "[ftw] Corpus: ${corpus_size} YAML files."

# ---- 4. Assemble the effective overrides file -----------------------
# go-ftw accepts a single --overrides file. We concatenate the shared
# overrides with the per-framework file so adapters can layer their own
# entries without duplicating the shared baseline.
SHARED_OVR="${SCRIPT_DIR}/ftw-overrides.yaml"
FRAMEWORK_OVR="${SCRIPT_DIR}/ftw-overrides-${FRAMEWORK}.yaml"
COMBINED_OVR="${BUILD_DIR}/ftw-overrides-combined-${FRAMEWORK}.yaml"

if [[ ! -f "${SHARED_OVR}" ]]; then
  echo "missing ${SHARED_OVR}" >&2
  exit 1
fi
if [[ ! -f "${FRAMEWORK_OVR}" ]]; then
  echo "missing ${FRAMEWORK_OVR}" >&2
  exit 1
fi

python3 - "${SHARED_OVR}" "${FRAMEWORK_OVR}" "${COMBINED_OVR}" <<'PY'
# Merge the shared overrides YAML with the per-framework overrides YAML
# into one go-ftw overrides file. Uses only the stdlib: no PyYAML
# dependency, because go-ftw overrides happen to be a strict enough
# subset that line-wise concatenation of the `overrides:` arrays is
# sufficient — we extract the list entries from each file and emit a
# new document with the union under a single `overrides:` key.
import sys, re, pathlib

shared_path, framework_path, out_path = sys.argv[1:4]

def extract_list_items(path: str) -> list[str]:
    text = pathlib.Path(path).read_text()
    items: list[str] = []
    in_overrides = False
    current: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if re.match(r'^overrides\s*:\s*(\[\s*\])?\s*$', stripped):
            in_overrides = stripped.endswith(':')
            # `overrides: []` — nothing to collect.
            continue
        if not in_overrides:
            continue
        if stripped.startswith('- '):
            if current:
                items.append('\n'.join(current))
                current = []
            current.append(stripped)
        elif stripped.startswith('  ') and current:
            current.append(stripped)
        elif stripped == '':
            if current:
                current.append('')
        else:
            # New top-level key — end of overrides list.
            if current:
                items.append('\n'.join(current))
                current = []
            in_overrides = False
    if current:
        items.append('\n'.join(current))
    return [i.rstrip() for i in items if i.strip()]

shared_items = extract_list_items(shared_path)
framework_items = extract_list_items(framework_path)

with open(out_path, 'w') as fh:
    fh.write('# Auto-generated by testing/ftw/run.sh -- do not edit by hand.\n')
    fh.write('# Source: ftw-overrides.yaml + ftw-overrides-<framework>.yaml\n')
    fh.write('overrides:\n')
    for item in shared_items + framework_items:
        for ln in item.splitlines():
            # Each list entry begins with "- "; subsequent lines start
            # with "  ". Indent the whole block by 2 spaces so it nests
            # correctly under the top-level `overrides:` key.
            fh.write('  ' + ln + '\n' if ln else '\n')
PY

echo "[ftw] overrides: ${COMBINED_OVR##*/}"

# ---- 5. Boot the example app (unless --skip-boot) -------------------
APP_PID=""
APP_PGID=""
cleanup() {
  if [[ -n "${APP_PGID}" ]]; then
    kill -TERM "-${APP_PGID}" 2>/dev/null || true
    sleep 1
    kill -KILL "-${APP_PGID}" 2>/dev/null || true
  elif [[ -n "${APP_PID}" ]] && kill -0 "${APP_PID}" 2>/dev/null; then
    kill "${APP_PID}" 2>/dev/null || true
    wait "${APP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

BOOT_TIMEOUT="${BOOT_TIMEOUT:-60}"

if [[ "${SKIP_BOOT}" != "1" ]]; then
  if [[ "${FRAMEWORK}" == "django" ]]; then
    APP_ENTRY="${REPO_ROOT}/examples/django_app/manage.py"
  else
    APP_ENTRY="${REPO_ROOT}/examples/${FRAMEWORK}_app/app.py"
  fi
  if [[ ! -f "${APP_ENTRY}" ]]; then
    echo "missing example app: ${APP_ENTRY}" >&2
    exit 1
  fi

  # Flask's dev server (`python app.py`) is too lenient with malformed
  # HTTP — some CRS 920-family tests send weird request lines and the
  # dev server responds with an HTML error page that go-ftw can't parse
  # ("malformed HTTP status code 'HTML>'"). Launch Flask under gunicorn
  # so we get a strict parser + clean 4xx responses. ASGI adapters use
  # uvicorn via the example's `__main__` block, which is already strict.
  case "${FRAMEWORK}" in
    flask)
      BOOT_CMD=(python -m gunicorn --workers 2 --worker-class sync
                -b "127.0.0.1:${PORT}"
                --chdir "${REPO_ROOT}/examples/flask_app"
                --access-logfile /dev/null --error-logfile -
                app:app)
      ;;
    django)
      # Run via `manage.py runserver`. We tried gunicorn here but the
      # nested env/--pythonpath/--env forms produced a process that
      # exited before logging, making CI debugging impossible. Django's
      # dev server is fine for FTW: like Flask, the 920 protocol-
      # enforcement family already runs under our 99% threshold.
      BOOT_CMD=(env "DJANGO_SETTINGS_MODULE=django_app.settings"
                "PYTHONPATH=${REPO_ROOT}/examples/django_app:${REPO_ROOT}/examples/shared:${REPO_ROOT}/src"
                python "${REPO_ROOT}/examples/django_app/manage.py"
                runserver "127.0.0.1:${PORT}" --noreload)
      ;;
    *)
      BOOT_CMD=(python "${APP_ENTRY}")
      ;;
  esac

  echo "[ftw] Starting ${FRAMEWORK} on :${PORT} (boot budget ${BOOT_TIMEOUT}s)..."
  # `setsid` puts the child in its own session so `kill -PGID` during
  # cleanup catches any worker subprocesses (uvicorn reloaders, etc.).
  ( cd "${REPO_ROOT}" &&
    setsid env FTW=1 PYCORAZA_PORT="${PORT}" "${BOOT_CMD[@]}" \
      </dev/null \
      > "${BUILD_DIR}/${FRAMEWORK}.stdout.log" \
      2> "${BUILD_DIR}/${FRAMEWORK}.stderr.log" &
    echo $! > "${BUILD_DIR}/${FRAMEWORK}.pid"
  )
  APP_PID="$(cat "${BUILD_DIR}/${FRAMEWORK}.pid")"
  APP_PGID="${APP_PID}"

  # Health-probe loop. We poll /healthz and accept any 2xx/3xx response;
  # the probe's only job is to confirm the server is accepting and
  # answering HTTP. Per-test assertions are go-ftw's job afterwards.
  retries="${BOOT_TIMEOUT}"
  status="000"
  while [[ "${retries}" -gt 0 ]]; do
    status="$(curl -sS -o /dev/null --connect-timeout 2 -w '%{http_code}' "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
    if [[ "${status}" =~ ^[23][0-9][0-9]$ ]]; then
      break
    fi
    if ! kill -0 "${APP_PID}" 2>/dev/null; then
      echo "[ftw] Example app exited before becoming ready." >&2
      tail -n 40 "${BUILD_DIR}/${FRAMEWORK}.stderr.log" 2>/dev/null || true
      tail -n 40 "${BUILD_DIR}/${FRAMEWORK}.stdout.log" 2>/dev/null || true
      exit 1
    fi
    sleep 1
    retries=$((retries - 1))
  done
  [[ "${retries}" -gt 0 ]] || {
    echo "[ftw] Example app did not come up within ${BOOT_TIMEOUT}s (last /healthz=${status})." >&2
    tail -n 40 "${BUILD_DIR}/${FRAMEWORK}.stderr.log" 2>/dev/null || true
    tail -n 40 "${BUILD_DIR}/${FRAMEWORK}.stdout.log" 2>/dev/null || true
    exit 1
  }
  echo "[ftw] Example app up (/healthz=${status})."
fi

# ---- 6. Run go-ftw --------------------------------------------------
OUT_JSON="${BUILD_DIR}/ftw-result-${FRAMEWORK}.json"

# Point every test at our running example adapter. CRS test YAMLs
# hardcode `dest_addr: 127.0.0.1` and `port: 80` in the input block;
# testoverride.input rewrites those in-memory without touching upstream.
FTW_CONFIG="${BUILD_DIR}/ftw-config-${FRAMEWORK}.yaml"
cat > "${FTW_CONFIG}" <<EOF
---
testoverride:
  input:
    dest_addr: 127.0.0.1
    port: ${PORT}
    protocol: http
EOF

set +e
"${FTW_BIN}" run \
  --config "${FTW_CONFIG}" \
  --dir "${CRS_TESTS_DIR}" \
  --overrides "${COMBINED_OVR}" \
  --debug=false \
  --connect-timeout 5s \
  --read-timeout 10s \
  --cloud \
  --output json \
  > "${OUT_JSON}" 2> "${BUILD_DIR}/ftw-stderr-${FRAMEWORK}.log"
ftw_exit=$?
set -e

if [[ "${ftw_exit}" -ne 0 ]]; then
  echo "[ftw] go-ftw exited with ${ftw_exit}; last 40 stderr lines:" >&2
  tail -n 40 "${BUILD_DIR}/ftw-stderr-${FRAMEWORK}.log" >&2 || true
fi

# ---- 7. Parse & enforce threshold -----------------------------------
if ! [[ -s "${OUT_JSON}" ]]; then
  echo "[ftw] go-ftw produced no output (exit=${ftw_exit})." >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  # go-ftw v2 JSON shape:
  #   {"run": <N>, "success": [...], "failed": [...], "ignored": [...], "skipped": [...], ...}
  total=$(jq -r '(.run // .stats.totalCount // .stats.total // 0)' "${OUT_JSON}")
  success=$(jq -r '((.success // []) | length) // .stats.success // .stats.passed // 0' "${OUT_JSON}")
  failed=$(jq -r '((.failed // []) | length) // .stats.failed // 0' "${OUT_JSON}")
  ignored=$(jq -r '((.ignored // []) | length) // .stats.skipped // .stats.ignored // 0' "${OUT_JSON}")
  skipped=$(jq -r '((.skipped // []) | length) // 0' "${OUT_JSON}")
  # v2's "skipped" = not matched by --include; "ignored" = excluded via
  # overrides. For threshold purposes, consider only what the WAF saw:
  # total - skipped - ignored.
  skipped=$(( skipped + ignored ))
else
  total=$(grep -oE '"run"[[:space:]]*:[[:space:]]*[0-9]+' "${OUT_JSON}" | head -1 | grep -oE '[0-9]+$' || echo 0)
  success=0; failed=0; skipped=0
fi

considered=$(( total - skipped ))
if [[ "${considered}" -le 0 ]]; then
  echo "[ftw] No tests were actually executed (total=${total}, skipped=${skipped})." >&2
  exit 1
fi
pct=$(awk -v s="${success}" -v c="${considered}" 'BEGIN { printf "%.2f", (s * 100.0) / c }')

echo ""
echo "========================================"
echo " go-ftw summary (${FRAMEWORK})"
echo "========================================"
echo "  total:     ${total}"
echo "  passed:    ${success}"
echo "  failed:    ${failed}"
echo "  skipped:   ${skipped}"
echo "  pass rate: ${pct}% (of ${considered} executed)"
echo "  threshold: ${THRESHOLD}%"
echo "  artifact:  ${OUT_JSON}"
echo "========================================"

pass_ok=$(awk -v p="${pct}" -v t="${THRESHOLD}" 'BEGIN { print (p+0 >= t+0) ? 1 : 0 }')
if [[ "${pass_ok}" -ne 1 ]]; then
  echo "[ftw] FAIL - ${pct}% < ${THRESHOLD}%" >&2
  exit 1
fi
echo "[ftw] PASS"
exit 0
