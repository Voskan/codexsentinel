#!/bin/sh
# Install codex-cli from GitHub Releases.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
#   sh install.sh [--version vX.Y.Z] [--dir /path/to/bin]
#
# Environment variables (overridden by flags):
#   CODEXSENTINEL_VERSION  release tag to install (default: latest release)
#   INSTALL_DIR            target directory (default: /usr/local/bin when
#                          writable, otherwise $HOME/.local/bin)
#
# The release binary is verified against the published checksums.txt when the
# release provides one. If no binary is published for the platform, the script
# falls back to "go install". It never edits shell startup files.

set -eu

REPO="Voskan/codexsentinel"
APP_NAME="codex-cli"
MODULE="github.com/Voskan/codexsentinel/v2/cmd/codex-cli"

VERSION="${CODEXSENTINEL_VERSION:-}"
INSTALL_DIR="${INSTALL_DIR:-}"

log() {
  printf '[codex-install] %s\n' "$*"
}

fail() {
  printf '[codex-install] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,16p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version requires a value"; VERSION="$2"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --dir) [ $# -ge 2 ] || fail "--dir requires a value"; INSTALL_DIR="$2"; shift 2 ;;
    --dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

detect_platform() {
  case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
  EXT=""
  if [ "$OS" = "windows" ]; then
    EXT=".exe"
  fi
}

choose_install_dir() {
  if [ -z "$INSTALL_DIR" ]; then
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
      INSTALL_DIR="/usr/local/bin"
    else
      INSTALL_DIR="$HOME/.local/bin"
    fi
  fi
  mkdir -p "$INSTALL_DIR" || fail "cannot create ${INSTALL_DIR}"
  INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"
}

download() {
  # download URL DEST: returns non-zero when the URL is unavailable.
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "curl or wget is required"
  fi
}

resolve_version() {
  if [ -n "$VERSION" ] && [ "$VERSION" != "latest" ]; then
    return
  fi
  VERSION=""
  if download "https://api.github.com/repos/${REPO}/releases/latest" "$TMP_DIR/latest.json" 2>/dev/null; then
    VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP_DIR/latest.json" | head -n 1)"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo ""
  fi
}

verify_checksum() {
  asset="$1"
  file="$2"
  if ! download "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" "$TMP_DIR/checksums.txt" 2>/dev/null; then
    log "warning: release ${VERSION} publishes no checksums.txt; skipping checksum verification"
    return 0
  fi
  expected="$(awk -v name="$asset" '$2 == name || $2 == "*"name {print $1}' "$TMP_DIR/checksums.txt" | head -n 1)"
  if [ -z "$expected" ]; then
    fail "checksums.txt has no entry for ${asset}"
  fi
  actual="$(sha256_of "$file")"
  if [ -z "$actual" ]; then
    fail "sha256sum or shasum is required to verify the download"
  fi
  if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
  fi
  log "checksum verified (${actual})"
}

install_release() {
  [ -n "$VERSION" ] || return 1
  asset="${APP_NAME}-${OS}-${ARCH}${EXT}"
  url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
  log "downloading ${url}"
  if ! download "$url" "$TMP_DIR/$asset" 2>/dev/null; then
    log "no release binary for ${OS}/${ARCH} in ${VERSION}"
    return 1
  fi
  verify_checksum "$asset" "$TMP_DIR/$asset"
  chmod 0755 "$TMP_DIR/$asset"
  mv "$TMP_DIR/$asset" "$INSTALL_DIR/${APP_NAME}${EXT}"
}

install_from_source() {
  command -v go >/dev/null 2>&1 || fail "no release binary is available and Go is not installed (https://go.dev/dl/)"
  ref="${VERSION:-latest}"
  log "building with go install ${MODULE}@${ref}"
  GOBIN="$INSTALL_DIR" go install -trimpath "${MODULE}@${ref}"
}

main() {
  detect_platform
  choose_install_dir
  TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t codexsentinel)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  trap 'exit 1' INT TERM

  resolve_version
  if ! install_release; then
    install_from_source
  fi

  target="$INSTALL_DIR/${APP_NAME}${EXT}"
  [ -x "$target" ] || fail "installation failed: ${target} not found"
  log "installed ${target}"
  "$target" version || true

  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) log "add ${INSTALL_DIR} to your PATH to run ${APP_NAME} from any directory, e.g.: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
  esac
}

main
