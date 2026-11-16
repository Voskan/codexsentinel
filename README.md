# CodexSentinel

[![Go](https://github.com/Voskan/codexsentinel/actions/workflows/go.yml/badge.svg)](https://github.com/Voskan/codexsentinel/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Voskan/codexsentinel.svg)](https://pkg.go.dev/github.com/Voskan/codexsentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

CodexSentinel is a static analyzer for Go modules. It loads the module once
with full type information, builds SSA and a call graph, and runs four kinds
of analysis over it:

- **Security**: type-aware rules and an interprocedural taint engine.
- **Dependencies**: known vulnerabilities, with call-graph reachability, plus license policy and a capability lock file.
- **Architecture**: layer rules, import cycles, god structs and leaking boundary types.
- **Code quality**: complexity, size, duplication, mutable global state and dead code.

Findings are written as SARIF 2.1.0, JSON, HTML or Markdown.

## Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Rules](#rules)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [CI integration](#ci-integration)
- [golangci-lint and go/analysis](#golangci-lint-and-goanalysis)
- [Development](#development)
- [License](#license)

## Features

**Interprocedural taint analysis.**
- Untrusted data is tracked from sources to sinks on SSA form. Sources are HTTP requests, environment variables, command-line arguments and similar inputs. Sinks are SQL queries, commands, file paths, outbound URLs, HTML responses and redirects.
- Function summaries carry taint across calls, closures, struct fields and interface calls. Calls are resolved through a VTA call graph.
- Sanitizers can clear taint for specific categories only.
- Every taint finding includes a source-to-sink trace, which the SARIF output emits as `codeFlows` so code scanning UIs show the path.
- File paths that come from local sources (environment, command line) are trusted. Only remote input reported for path traversal.

**Current Go APIs.**
- Access through Go 1.24 `os.Root` (`os.OpenRoot`) is treated as confined and not reported as path traversal.
- Go 1.25 `http.CrossOriginProtection` counts as CSRF protection.

**Sensitive data in logs.**
- `log/slog`, `go.uber.org/zap`, `github.com/rs/zerolog` and the standard `log` package are inspected for credentials and personal data.
- A struct that defines its own log representation is not reported: `slog.LogValuer`, `zapcore.ObjectMarshaler` or `zerolog.LogObjectMarshaler`.

**Dependency audit** (opt-in, it needs network access).
- Modules from `go.mod` and the Go standard library version (`go`/`toolchain` directive) are checked against OSV and the Go vulnerability database. GitHub Security Advisories are added when `GITHUB_TOKEN` is set.
- With the call graph, each vulnerability is marked reachable or unreachable from the module's code.
- Licenses are classified and checked against allow and deny lists.

**Capability lock file.**
- `codex-cli caps lock` records which privileged capabilities each dependency uses from reachable code: file system, network, environment, process execution, `reflect`, `unsafe`, cgo and plugins.
- `codex-cli caps verify` fails when an upgraded dependency starts using a capability the lock file does not approve.

**Architecture guard.**
- Configurable layer dependency rules and import cycle detection.
- God structs: too many methods, or many fields combined with behavior.
- Boundary checks that report domain types leaking through other layers' exported APIs.

**Change-focused scanning.**
- `--diff <ref>` reports only findings on lines changed since a git reference.
- `--baseline` hides findings already recorded in a baseline file. Fingerprints are stable across line shifts.
- `--fix` applies the mechanical fixes that rules provide.

**Suppressions.** Inline `//codex:ignore <rule> -- <reason>` directives, an ignore file with doublestar globs, and an optional requirement that every suppression gives a reason.

**Custom rules.** Structural YAML pattern rules with metavariables, type filters and autofixes.

**Editor and linter integration.** The built-in rules are exported as `go/analysis` analyzers (`pkg/codexlint`) for gopls, multichecker binaries and golangci-lint v2 module plugins.

## Installation

Build from source with Go 1.24 or newer:

```bash
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
```

Or use the install script. It downloads a release binary and verifies it
against the release checksums, or falls back to `go install` when no binary
is published for your platform:

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
```

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh -s -- --version v1.2.3 --dir "$HOME/bin"
```

The script never edits shell startup files; it prints a hint when the target
directory is not on your `PATH`.

Container image, built from this repository:

```bash
docker build -t codexsentinel .
```

```bash
docker run --rm -v "$PWD:/workspace" codexsentinel scan . --format sarif --out results.sarif
```

## Usage

```bash
codex-cli scan .                                   # SARIF report in scan_reports/
codex-cli scan ./... --format json --out report.json
codex-cli scan . --format html --out report.html
codex-cli scan . --format markdown --out report.md
codex-cli scan . --format json --out -             # write the report to stdout
codex-cli scan . --severity high                   # only high and critical findings
codex-cli scan . --strict                          # exit code 1 when findings remain
codex-cli scan . --deps                            # dependency audit only
codex-cli scan . --no-cache                        # ignore the analysis cache
codex-cli cache status                             # cache location and size
codex-cli cache clean                              # remove cached results
```

Package-level results are cached on disk and reused while a package, the
packages it imports, the configuration and the analyzer are unchanged.

The target may be a module directory, a package pattern ending in `/...`, or a
single `.go` file. Findings are reported relative to the module root.

### Pull requests and legacy code

```bash
# Only findings on lines changed since origin/main (untracked files count as changed)
codex-cli scan . --diff origin/main --strict

# Record the current findings once, then report only new ones
codex-cli baseline create . --out .codexsentinel.baseline.json
codex-cli scan . --baseline .codexsentinel.baseline.json --strict
```

### Automatic fixes

```bash
codex-cli scan . --fix
```

`--fix` rewrites the source files with the suggested fixes of the findings,
for example re-enabling TLS certificate verification, requiring TLS 1.2, or the style fixes of the YAML
rules in `assets/rules/style-rules.yaml`. Review the diff before committing.

### Dependency capabilities

```bash
codex-cli caps inspect .     # capabilities per dependency, with a call path as evidence
codex-cli caps lock .        # write .codexsentinel.caps.json
codex-cli caps verify .      # exit code 1 when a dependency gained capabilities
```

When the lock file exists, `scan` also reports capability escalations against
it as `supply-chain-capability-escalation` findings. The check is offline;
set `dependencies.check_capabilities: false` to turn it off.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed; no findings at or above the failure threshold |
| 1 | Findings remain with `--strict` or `report.fail_on_severity`, `caps verify` found escalations, or the scan failed |

## Rules

### Built-in security rules

| Rule ID | Severity | CWE | OWASP 2025 |
| --- | --- | --- | --- |
| `api-excessive-data-exposure` | High | CWE-200 | A01 |
| `api-mass-assignment` | High | CWE-915 | A01 |
| `archive-zip-slip` | Critical | CWE-22 | A01 |
| `csrf-missing-protection` | Medium | CWE-352 | A01 |
| `idor-unscoped-mutation` | Medium | CWE-639 | A01 |
| `path-traversal` | High | CWE-22 | A01 |
| `ssrf` | Medium | CWE-918 | A01 |
| `ssrf-missing-ip-guard` | Medium | CWE-918 | A01 |
| `websocket-origin-bypass` | High | CWE-346 | A01 |
| `cors-wildcard-credentials` | High | CWE-942 | A02 |
| `debug-endpoint-exposed` | Medium | CWE-489 | A02 |
| `graphql-introspection-enabled` | Low | CWE-200 | A02 |
| `http-server-missing-timeout` | High | CWE-400 | A02 |
| `insecure-file-permissions` | Medium | CWE-732 | A02 |
| `grpc-insecure-credentials` | High | CWE-319 | A04 |
| `crypto-weak-cipher` | High | CWE-327 | A04 |
| `crypto-weak-hash` | Medium | CWE-328 | A04 |
| `crypto-weak-rand` | High | CWE-338 | A04 |
| `crypto-weak-rsa` | High | CWE-326 | A04 |
| `jwt-alg-none` | Critical | CWE-347 | A04 |
| `jwt-weak-secret` | High | CWE-326 | A04 |
| `tls-insecure-config` | High | CWE-295 | A04 |
| `command-injection` | High | CWE-78 | A05 |
| `sql-injection` | High | CWE-89 | A05 |
| `xss` | High | CWE-79 | A05 |
| `archive-decompression-bomb` | Medium | CWE-409 | A06 |
| `context-propagation-missing` | Medium | CWE-400 | A06 |
| `graphql-unbounded-query` | Medium | CWE-400 | A06 |
| `grpc-server-missing-limits` | Medium | CWE-400 | A06 |
| `http-client-unsafe` | Medium | CWE-400 | A06 |
| `http-unbounded-body-read` | High | CWE-400 | A06 |
| `untrusted-slice-allocation` | High | CWE-789 | A06 |
| `unsafe-memory-manipulation` | High | CWE-119 | A06 |
| `auth-hardcoded-credential` | Critical | CWE-798 | A07 |
| `auth-non-constant-time-compare` | High | CWE-208 | A07 |
| `cookie-insecure-samesite` | Medium | CWE-1275 | A07 |
| `cookie-missing-httponly` | Medium | CWE-1004 | A07 |
| `cookie-missing-secure` | Medium | CWE-614 | A07 |
| `hardcoded-secret` | High | CWE-798 | A07 |
| `jwt-missing-alg-check` | High | CWE-347 | A07 |
| `jwt-unverified-parse` | High | CWE-347 | A07 |
| `unsafe-gob-decode` | High | CWE-502 | A08 |
| `sensitive-data-in-logs` | High | CWE-532 | A09 |
| `security-err-ignored` | Critical | CWE-252 | A10 |

Rules resolve calls through type information, so renamed imports are
recognized and look-alike local functions are not. The listed severity is the
default; some rules lower it for weaker evidence. For example, `ssrf` reports
a request whose URL is not built from a fixed host as Low.

### Reliability rules

These rules report resources and goroutines that are never released. Their
findings use the `reliability` category.

| Rule ID | Severity | CWE | Reported when |
|---|---|---|---|
| `tx-network-io` | High | CWE-400 | A database transaction is open while the code, directly or through called functions, makes an HTTP, gRPC or network call or sleeps |
| `lock-blocking-io` | Medium | CWE-833 | A `sync.Mutex` or `sync.RWMutex` is held across such a call |
| `sql-tx-missing-rollback` | High | CWE-404 | A transaction has no deferred `Rollback` and a return after `Begin` neither commits nor rolls back |
| `http-body-unclosed` | High | CWE-404 | A response body is neither closed nor handed to other code |
| `sql-rows-unclosed` | High | CWE-404 | Rows from `Query` are neither closed nor handed to other code |
| `defer-in-loop` | Medium | CWE-400 | `defer` runs in a loop body of the same function |
| `goroutine-channel-leak` | Medium | CWE-400 | A goroutine sends on an unbuffered channel that its caller can stop reading after cancellation or an early return |

### Taint analysis

The taint engine reports `sql-injection`, `command-injection`,
`path-traversal`, `ssrf`, `xss` and `open-redirect` findings with a trace.
Custom sources, sinks and sanitizers are configured under `taint` (see
[Configuration](#configuration)). When a built-in rule and the taint engine
report the same line, the finding with the longer trace is kept.

### Dependencies, architecture and metrics

| Rule ID | Reported when |
| --- | --- |
| `dependency-vulnerability` | A dependency or the standard library version has a known vulnerability |
| `license-denied` | A dependency license is denied or not allowed |
| `high-entropy-string` | Vendored dependency code contains a string that looks like a secret |
| `supply-chain-capability-escalation` | A dependency uses capabilities missing from the lock file |
| `arch-layer-violation` | A package imports a layer it may not depend on |
| `arch-import-cycle` | Packages of the module import each other in a cycle |
| `arch-god-struct` | A struct has too many methods, or too many fields while also carrying behavior |
| `arch-boundary-type-leak` | A layer's exported API exposes types of a layer it should hide |
| `high-complexity` | Cyclomatic complexity exceeds `metrics.max_cyclomatic` |
| `large-function`, `large-file` | Length exceeds `metrics.max_function_loc` / `metrics.max_file_loc` |
| `code-duplication` | Function bodies of at least `metrics.min_duplicate_loc` lines are identical |
| `global-variable` | A package variable holds mutable shared state |
| `dead-code` | A function is unreachable from the program's entry points |
| `ignore-missing-reason` | A suppression has no reason while `suppression.require_ignore_reason` is set |

### YAML rules

The default pattern rules from [assets/rules](assets/rules) are compiled into
the binary, so they apply wherever `codex-cli` runs. Rules from the
directories and files in `rules.rule_paths` and `rules.rule_files` are added
to them; a rule with the same ID replaces the default one.

```yaml
id: go.style.strings-replace-all
title: Use strings.ReplaceAll
severity: LOW
match:
  pattern: "strings.Replace($S, $OLD, $NEW, -1)"
fix: "strings.ReplaceAll($S, $OLD, $NEW)"
```

`$X` matches any expression and `$...` any number of arguments. Filters can
restrict a metavariable by type or require it to be non-constant. See
[assets/rules](assets/rules) for complete examples.

## Configuration

`codex-cli` looks for `.codexsentinel.yaml`, `.codexsentinel.yml`,
`codex.yaml` or `.codex.yml` in the current directory. Pass `--config` to use
another file. Unknown keys and invalid values are rejected. The defaults are:

```yaml
version: 1
scan:
  include_tests: false
  excluded_paths: [vendor, testdata, node_modules, .git]
  concurrency: 0                 # 0 uses all CPUs
  enable_cache: true             # reuse results of unchanged packages
  cache_dir: ""                  # default: the user cache directory
rules:
  enabled: ["*"]                 # rule IDs or globs
  disabled: []
  severity_overrides: {}         # e.g. {ssrf: high}
  rule_paths: []
  rule_files: []
taint:
  enable: true
  interprocedural: true
  custom_sources: []
  custom_sinks: []
  custom_sanitizers: []
architecture:
  enable: true
  layers: {}                     # layer name -> path segments or globs; empty uses a Clean Architecture layout
  allowed_deps: {}               # layer name -> layers it may import
  check_cycles: true
  check_god_structs: true
  check_boundaries: true
  god_struct_max_methods: 15
  god_struct_max_fields: 20
metrics:
  enable: true
  max_cyclomatic: 15             # 0 disables a threshold
  max_function_loc: 80
  max_file_loc: 600
  min_duplicate_loc: 10
  enable_duplication: true
  enable_dead_code: true
  enable_globals: true
dependencies:
  enable: false                  # queries OSV/GHSA over the network
  check_vulnerabilities: true
  check_reachability: true
  check_capabilities: true       # offline; only when the lock file exists
  capability_lockfile: .codexsentinel.caps.json
  check_licenses: true
  allow_licenses: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0]
  deny_licenses: [AGPL-3.0, GPL-3.0, GPL-2.0, SSPL-1.0, BSL-1.1]
suppression:
  ignore_file: .codexsentinel.ignore
  enable_inline_ignore: true
  require_ignore_reason: false
  min_confidence: 0.5            # findings below this confidence are dropped
report:
  formats: [sarif]
  output_dir: scan_reports
  fail_on_severity: ""           # e.g. high: exit 1 on high or critical findings
```

[codex.yaml](codex.yaml) is the configuration this repository uses for its own scan.

## Suppressing findings

Fix the finding when you can. For false positives, put the suppression next
to the code with a reason:

```go
resp, err := client.Do(req) //codex:ignore ssrf -- the URL is the configured API endpoint
```

A directive covers the next line when it stands on its own line, or the whole
declaration it documents. List several rules with commas, or omit the rule to
suppress all rules on that line.

`.codexsentinel.ignore` lists paths relative to the project root, optionally
followed by rule IDs, or a rule ID alone to disable it everywhere:

```text
**/*.pb.go
/vendor/
internal/legacy/** sql-injection,xss
cmd/tool/main.go:42 path-traversal
```

`codex-cli mark <file[:line]> --rule <id> --reason "<why>"` appends such an
entry.

## CI integration

GitHub Actions with code scanning:

```yaml
name: CodexSentinel
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24.x'
      - run: go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
      - run: codex-cli scan . --strict --severity high --format sarif --out results.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

For pull requests, scan only the changed lines with
`codex-cli scan . --diff origin/${{ github.base_ref }} --strict`. This needs
`fetch-depth: 0`, as above, so the base branch is available.

This repository runs `go vet`, the race-enabled tests, a self-scan with
`--strict --severity medium` and `caps verify` on every push to `main` and every pull request
([.github/workflows/go.yml](.github/workflows/go.yml)).

## golangci-lint and go/analysis

`pkg/codexlint` exposes every built-in rule as an `analysis.Analyzer` named
`codex_<rule_id>`, for example `codex_sql_injection`. A standalone checker:

```go
package main

import (
	"github.com/Voskan/codexsentinel/pkg/codexlint"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() { multichecker.Main(codexlint.Analyzers(nil)...) }
```

For golangci-lint v2, register `codexlint.NewPlugin` in a module plugin and
build a custom binary with `golangci-lint custom`. See the package
documentation for the registration snippet and the supported settings
(`enabled`, `disabled`, `min_confidence`, `enable_inline_ignore`).

The analyzers run per package. Interprocedural taint, dependency, architecture
and metrics analyses need the whole program and are only available in
`codex-cli scan`.

## Development

```bash
make build      # build/codex-cli
make test       # go test -race ./...
go vet ./...
```

At the time of writing, `go test -cover ./...` reports 72.6% total statement
coverage. See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture overview
and how to write and test rules. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
