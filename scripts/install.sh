#!/usr/bin/env bash

set -e

REPO="Voskan/codexsentinel"
APP_NAME="codex-cli"
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
  # Use sed instead of grep -P for better compatibility
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' || true)
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

  # For now, use go install as fallback since we don't have pre-built binaries
  log "No pre-built binaries available yet. Using go install instead..."
  
  # Check if Go is installed
  if ! command -v go &> /dev/null; then
    fail "Go is not installed. Please install Go first: https://golang.org/dl/"
  fi
  
  # Install via go install
  log "Installing via go install..."
  go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest || fail "Failed to install via go install"
  
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
  
  # Make it globally available
  setup_global_access
  
  # Create convenient alias
  create_alias
  
  "$DEST" version || log "Run 'codex-cli version' to verify"
}

setup_global_access() {
  log "Setting up global access..."
  
  # Get the directory where the binary is installed
  BIN_DIR=$(dirname "$DEST")
  
  # Add to PATH permanently
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    SHELL_RC="$HOME/.zshrc"
    if [ ! -f "$SHELL_RC" ]; then
      SHELL_RC="$HOME/.bash_profile"
    fi
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
    log "Added $BIN_DIR to PATH in $SHELL_RC"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    SHELL_RC="$HOME/.bashrc"
    if [ -f "$HOME/.zshrc" ]; then
      SHELL_RC="$HOME/.zshrc"
    fi
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
    log "Added $BIN_DIR to PATH in $SHELL_RC"
  elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash)
    SHELL_RC="$HOME/.bashrc"
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
    log "Added $BIN_DIR to PATH in $SHELL_RC"
  fi
}

create_alias() {
  log "Creating convenient alias..."
  
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    SHELL_RC="$HOME/.zshrc"
    if [ ! -f "$SHELL_RC" ]; then
      SHELL_RC="$HOME/.bash_profile"
    fi
    echo "alias codex=\"$APP_NAME\"" >> "$SHELL_RC"
    log "Created alias 'codex' in $SHELL_RC"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    SHELL_RC="$HOME/.bashrc"
    if [ -f "$HOME/.zshrc" ]; then
      SHELL_RC="$HOME/.zshrc"
    fi
    echo "alias codex=\"$APP_NAME\"" >> "$SHELL_RC"
    log "Created alias 'codex' in $SHELL_RC"
  elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash)
    SHELL_RC="$HOME/.bashrc"
    echo "alias codex=\"$APP_NAME\"" >> "$SHELL_RC"
    log "Created alias 'codex' in $SHELL_RC"
  fi
  
  log "✅ Installation complete! You can now use:"
  log "   - '$APP_NAME version' (full command)"
  log "   - 'codex version' (convenient alias)"
  log "   - Restart your terminal or run 'source $SHELL_RC' to use immediately"
}

install_binary
