#!/bin/sh
# Install a specific codex-cli release.
#
# Usage:
#   sh install-with-version.sh vX.Y.Z [--dir /path/to/bin]
#   curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install-with-version.sh | sh -s -- vX.Y.Z
#
# This is a thin wrapper around install.sh, which downloads the release
# binary, verifies its checksum and falls back to "go install".

set -eu

if [ $# -lt 1 ] || [ -z "$1" ]; then
  echo "usage: install-with-version.sh <version> [--dir DIR]" >&2
  exit 2
fi
version="$1"
shift

script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
if [ -n "$script_dir" ] && [ -f "$script_dir/install.sh" ]; then
  exec sh "$script_dir/install.sh" --version "$version" "$@"
fi

url="https://raw.githubusercontent.com/Voskan/codexsentinel/${version}/scripts/install.sh"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" | sh -s -- --version "$version" "$@"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O - "$url" | sh -s -- --version "$version" "$@"
else
  echo "curl or wget is required" >&2
  exit 1
fi
