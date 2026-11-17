#!/usr/bin/env bash
# Scans both benchmark corpora with codex-cli and, when they are installed,
# with gosec (standalone or through golangci-lint) and govulncheck, then
# prints a Markdown table with findings, wall time and peak memory.
#
# Usage: benchmarks/run_comparison.sh
# Nothing is written to the repository; temporary files go to a temp dir.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# measure FILE CMD...: runs CMD in the current directory and stores
# "<seconds> <peak MiB>" in FILE. The exit status of CMD is ignored because
# scanners exit non-zero when they report findings.
measure() {
  local out="$1"
  shift
  local stats="$work/time.txt"
  if /usr/bin/time -l true >/dev/null 2>&1; then # BSD/macOS
    /usr/bin/time -l "$@" >"$work/stdout.txt" 2>"$stats" || true
    awk '/ real /{s=$1} /maximum resident set size/{m=$1/1048576} END{printf "%.2f %.0f\n", s, m}' "$stats" >"$out"
  else # GNU time
    /usr/bin/time -v "$@" >"$work/stdout.txt" 2>"$stats" || true
    awk -F': ' '/Elapsed \(wall clock\)/{n=split($2,t,":"); s=(n==3?t[1]*3600+t[2]*60+t[3]:t[1]*60+t[2])} /Maximum resident set size/{m=$2/1024} END{printf "%.2f %.0f\n", s, m}' "$stats" >"$out"
  fi
}

echo "Building codex-cli..." >&2
(cd "$repo" && go build -trimpath -o "$work/codex-cli" ./cmd/codex-cli)
export CODEXSENTINEL_CACHE_DIR="$work/cache"

rows=()
for app in vulnerable-app safe-app; do
  dir="$repo/benchmarks/corpus/$app"
  cd "$dir"

  measure "$work/m.txt" "$work/codex-cli" scan . --severity low --no-cache --format agent --out "$work/codex.txt"
  read -r secs mib <"$work/m.txt"
  n="$(grep -c '^ISSUE ' "$work/codex.txt" || true)"
  rows+=("| codex-cli | $app | $n | $secs | $mib |")

  if command -v gosec >/dev/null; then
    measure "$work/m.txt" gosec -quiet -fmt json -out "$work/gosec.json" ./...
    read -r secs mib <"$work/m.txt"
    n="$(grep -c '"rule_id"' "$work/gosec.json" || true)"
    rows+=("| gosec | $app | $n | $secs | $mib |")
  elif command -v golangci-lint >/dev/null; then
    if golangci-lint run --help 2>/dev/null | grep -q -- '--default'; then
      lint=(golangci-lint run --default=none --enable=gosec --max-issues-per-linter=0 --max-same-issues=0 ./...)
    else
      lint=(golangci-lint run --disable-all --enable=gosec --max-issues-per-linter=0 --max-same-issues=0 ./...)
    fi
    measure "$work/m.txt" "${lint[@]}"
    read -r secs mib <"$work/m.txt"
    n="$(grep -c '(gosec)$' "$work/stdout.txt" || true)"
    rows+=("| gosec (golangci-lint) | $app | $n | $secs | $mib |")
  fi

  if command -v govulncheck >/dev/null; then
    measure "$work/m.txt" govulncheck ./...
    read -r secs mib <"$work/m.txt"
    n="$(grep -c '^Vulnerability #' "$work/stdout.txt" || true)"
    rows+=("| govulncheck | $app | $n | $secs | $mib |")
  fi
done

echo "| Tool | Corpus | Findings | Time (s) | Peak memory (MiB) |"
echo "| --- | --- | ---: | ---: | ---: |"
printf '%s\n' "${rows[@]}"
