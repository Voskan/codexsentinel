#!/bin/sh
# Render the Homebrew formula for a release.
#
# Usage:
#   sh scripts/homebrew-formula.sh TAG CHECKSUMS [TEMPLATE] > codexsentinel.rb
#
#   TAG        release tag, e.g. v2.0.0
#   CHECKSUMS  the release's checksums.txt ("<sha256>  codex-cli-<os>-<arch>")
#   TEMPLATE   formula template (default: packaging/homebrew/codexsentinel.rb
#              next to this script's repository)
#
# The formula installs the darwin and linux binaries for amd64 and arm64; the
# script fails when checksums.txt lacks any of them.

set -eu

fail() {
  printf 'homebrew-formula: %s\n' "$*" >&2
  exit 1
}

[ $# -ge 2 ] && [ $# -le 3 ] || fail "usage: $0 TAG CHECKSUMS [TEMPLATE]"

TAG="$1"
CHECKSUMS="$2"
TEMPLATE="${3:-$(dirname "$0")/../packaging/homebrew/codexsentinel.rb}"

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "tag must look like vX.Y.Z, got: $TAG" ;;
esac
case "$TAG" in
  *-*) fail "pre-release tags are not published to Homebrew: $TAG" ;;
esac
VERSION="${TAG#v}"

# CHECKSUMS may be a pipe such as <(...), so it is read only once.
[ -r "$CHECKSUMS" ] || fail "checksums file not found: $CHECKSUMS"
[ -f "$TEMPLATE" ] || fail "template not found: $TEMPLATE"
SUMS="$(cat "$CHECKSUMS")"

sha_for() {
  asset="codex-cli-$1"
  sum="$(printf '%s\n' "$SUMS" | awk -v name="$asset" '$2 == name || $2 == "*"name {print $1}' | head -n 1)"
  printf '%s' "$sum" | grep -Eq '^[0-9a-f]{64}$' || fail "no SHA-256 for ${asset} in ${CHECKSUMS}"
  printf '%s' "$sum"
}

DARWIN_ARM64="$(sha_for darwin-arm64)"
DARWIN_AMD64="$(sha_for darwin-amd64)"
LINUX_ARM64="$(sha_for linux-arm64)"
LINUX_AMD64="$(sha_for linux-amd64)"

sed \
  -e "s/@VERSION@/${VERSION}/g" \
  -e "s/@SHA256_DARWIN_ARM64@/${DARWIN_ARM64}/g" \
  -e "s/@SHA256_DARWIN_AMD64@/${DARWIN_AMD64}/g" \
  -e "s/@SHA256_LINUX_ARM64@/${LINUX_ARM64}/g" \
  -e "s/@SHA256_LINUX_AMD64@/${LINUX_AMD64}/g" \
  "$TEMPLATE"
