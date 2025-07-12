#!/usr/bin/env bash

set -e

REPO="Voskan/codexsentinel"
APP_NAME="codex-cli"

log() {
  echo "[codex-install] $1"
}

fail() {
  echo "[codex-install] ❌ $1" >&2
  exit 1
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
  fail "Go is not installed. Please install Go first: https://golang.org/dl/"
fi

# Check if git is available for version info
if ! command -v git &> /dev/null; then
  log "Warning: git not found, using default version info"
  VERSION_INFO="dev"
  BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  GIT_COMMIT="unknown"
else
  # Get version info for ldflags
  VERSION_INFO=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
  BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
  
  log "Version info: $VERSION_INFO (commit: $GIT_COMMIT, built: $BUILD_TIME)"
fi

# Build LDFLAGS
LDFLAGS="-X github.com/Voskan/codexsentinel/internal/version.Version=$VERSION_INFO -X github.com/Voskan/codexsentinel/internal/version.BuildDate=$BUILD_TIME -X github.com/Voskan/codexsentinel/internal/version.Commit=$GIT_COMMIT"

log "Installing CodexSentinel with version info..."
go install -ldflags "$LDFLAGS" github.com/Voskan/codexsentinel/cmd/codex-cli@latest || fail "Failed to install via go install"

# Find the installed binary
if command -v codex-cli &> /dev/null; then
  DEST=$(which codex-cli)
  log "✅ Installed codex-cli to $DEST"
else
  # Try common locations
  for dir in "$HOME/go/bin" "/usr/local/bin" "/usr/bin"; do
    if [ -f "$dir/codex-cli" ]; then
      DEST="$dir/codex-cli"
      log "✅ Found codex-cli at $DEST"
      break
    fi
  done
  
  if [ -z "$DEST" ]; then
    fail "Could not find installed codex-cli binary"
  fi
fi

# Test the installation
log "Testing installation..."
"$DEST" version

log "✅ Installation complete! You can now use:"
log "   - 'codex-cli version' (full command)"
log "   - 'codex-cli scan .' (scan current directory)"
log "   - 'codex-cli help' (show all commands)" 