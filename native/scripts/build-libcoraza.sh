#!/usr/bin/env bash
# Build libcoraza.so from the pinned upstream tag into $LIBCORAZA_PREFIX.
#
# Invoked by:
#   * `cibuildwheel` via `[tool.cibuildwheel] before-all` in pyproject.toml.
#   * developers locally from a fresh clone.
#   * `.github/workflows/ci.yml` to cache a prebuilt artifact.
#
# Reads pinned versions from native/version.txt.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NATIVE_DIR="$(cd "${HERE}/.." && pwd)"
REPO_ROOT="$(cd "${NATIVE_DIR}/.." && pwd)"

# shellcheck disable=SC1091
source "${NATIVE_DIR}/version.txt"

: "${LIBCORAZA_PREFIX:=${REPO_ROOT}/build/libcoraza}"
: "${JOBS:=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

install_go() {
  if command -v go >/dev/null 2>&1; then
    local have
    have="$(go env GOVERSION 2>/dev/null || echo unknown)"
    echo "go already installed: ${have}"
    return 0
  fi
  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
  esac
  local os
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) echo "unsupported os $(uname -s)" >&2; exit 1 ;;
  esac
  local url="https://go.dev/dl/go${GO_VERSION}.${os}-${arch}.tar.gz"
  local dest="/opt/go-${GO_VERSION}"
  mkdir -p /opt
  echo "downloading ${url} -> ${dest}"
  curl -fsSL "${url}" | tar -C /opt -xzf -
  mv /opt/go "${dest}"
  export PATH="${dest}/bin:${PATH}"
}

install_swig() {
  if command -v swig >/dev/null 2>&1; then
    local have
    have="$(swig -version 2>/dev/null | sed -n 's/^SWIG Version //p')"
    echo "swig already installed: ${have}"
    return 0
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y swig automake autoconf libtool pkgconf-pkg-config || true
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update && apt-get install -y swig automake autoconf libtool pkg-config
  fi
  command -v swig >/dev/null 2>&1 || {
    echo "swig install failed — install SWIG ${SWIG_VERSION}+ manually" >&2
    exit 1
  }
}

clone_libcoraza() {
  local dir="${NATIVE_DIR}/libcoraza"
  if [[ -d "${dir}/.git" ]]; then
    echo "libcoraza already checked out at ${dir}"
    git -C "${dir}" fetch --tags --quiet
    git -C "${dir}" checkout --quiet "${LIBCORAZA_TAG}"
    return 0
  fi
  echo "cloning libcoraza (${LIBCORAZA_TAG})"
  git clone --quiet https://github.com/corazawaf/libcoraza "${dir}"
  git -C "${dir}" checkout --quiet "${LIBCORAZA_TAG}"
}

build_libcoraza() {
  local dir="${NATIVE_DIR}/libcoraza"
  mkdir -p "${LIBCORAZA_PREFIX}"
  pushd "${dir}" >/dev/null
  # Upstream Makefile.am requires a ChangeLog file but upstream repo
  # doesn't ship one. `automake` fails without it.
  [[ -f ChangeLog ]] || touch ChangeLog
  if [[ -x build.sh ]]; then
    ./build.sh
  fi
  ./configure --prefix="${LIBCORAZA_PREFIX}"
  make -j"${JOBS}"
  make install
  popd >/dev/null
}

fetch_crs() {
  local rules_dir="${REPO_ROOT}/src/pycoraza/coreruleset/rules"
  if [[ -f "${rules_dir}/.crs-tag" ]] && [[ "$(cat "${rules_dir}/.crs-tag")" == "${CRS_TAG}" ]]; then
    echo "CRS ${CRS_TAG} already present at ${rules_dir}"
    return 0
  fi
  echo "fetching OWASP coreruleset ${CRS_TAG}"
  mkdir -p "${rules_dir}"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_TAG}.tar.gz" \
    | tar -C "${tmp}" -xzf -
  rm -rf "${rules_dir}/rules" "${rules_dir}/crs-setup.conf.example" \
         "${rules_dir}/REQUEST-"*.conf "${rules_dir}/RESPONSE-"*.conf 2>/dev/null || true
  local src="${tmp}/coreruleset-${CRS_TAG#v}"
  cp -R "${src}/rules" "${rules_dir}/rules"
  cp "${src}/crs-setup.conf.example" "${rules_dir}/crs-setup.conf.example"
  echo "${CRS_TAG}" > "${rules_dir}/.crs-tag"
  rm -rf "${tmp}"
}

main() {
  echo "=== pycoraza: build-libcoraza ==="
  echo "  LIBCORAZA_TAG = ${LIBCORAZA_TAG}"
  echo "  CRS_TAG       = ${CRS_TAG}"
  echo "  GO_VERSION    = ${GO_VERSION}"
  echo "  PREFIX        = ${LIBCORAZA_PREFIX}"
  install_go
  install_swig
  clone_libcoraza
  build_libcoraza
  fetch_crs
  echo "=== build-libcoraza: done ==="
  if [[ -f "${LIBCORAZA_PREFIX}/lib/libcoraza.so" ]]; then
    echo "artifact: ${LIBCORAZA_PREFIX}/lib/libcoraza.so"
  fi
}

main "$@"
