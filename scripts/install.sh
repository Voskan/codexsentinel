#!/usr/bin/env bash

set -e

REPO="Voskan/codexsentinel"
APP_NAME="codex"
INSTALL_DIR="/usr/local/bin"
FALLBACK_DIR="$HOME/.local/bin"

log() {
  echo "[codex-install] $1"
}

fail() {
  echo "[codex-install] ❌ $1" >&2
  exit 1
}

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)   OS="linux" ;;
    Darwin)  OS="darwin" ;;
    MINGW*|MSYS*) OS="windows" ;;
    *) fail "Unsupported OS: $OS" ;;
  esac

  case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    arm64)   ARCH="arm64" ;;
    aarch64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $ARCH" ;;
  esac

  echo "${OS}_${ARCH}"
}

fetch_latest_version() {
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -oP '"tag_name": "\K(.*)(?=")' || true)
  if [ -z "$LATEST_TAG" ]; then
    log "No release found, using 'main' branch"
    echo "main"
  else
    echo "$LATEST_TAG"
  fi
}

install_binary() {
  PLATFORM=$(detect_platform)
  VERSION=$(fetch_latest_version)

  if [[ "$PLATFORM" == windows_* ]]; then
    APP_NAME="${APP_NAME}.exe"
  fi

  if [ "$VERSION" = "main" ]; then
    URL="https://raw.githubusercontent.com/${REPO}/main/builds/${PLATFORM}/${APP_NAME}"
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${APP_NAME}-${PLATFORM}"
  fi

  TMP_FILE="$(mktemp)"
  log "Downloading $URL"
  curl -fsSL "$URL" -o "$TMP_FILE" || fail "Failed to download binary"

  chmod +x "$TMP_FILE"

  if [ -w "$INSTALL_DIR" ]; then
    DEST="$INSTALL_DIR/$APP_NAME"
  else
    mkdir -p "$FALLBACK_DIR"
    DEST="$FALLBACK_DIR/$APP_NAME"
    export PATH="$FALLBACK_DIR:$PATH"
    log "No sudo access; installing to $FALLBACK_DIR"
  fi

  mv "$TMP_FILE" "$DEST" || fail "Failed to move binary to $DEST"

  log "✅ Installed $APP_NAME to $DEST"
  "$DEST" version || log "Run '$APP_NAME version' to verify"
}

install_binary
