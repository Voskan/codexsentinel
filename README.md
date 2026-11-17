# CodexSentinel

[![Go](https://github.com/Voskan/codexsentinel/actions/workflows/go.yml/badge.svg)](https://github.com/Voskan/codexsentinel/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Voskan/codexsentinel.svg)](https://pkg.go.dev/github.com/Voskan/codexsentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

CodexSentinel is an interprocedural static analyzer for modern Go (Go 1.24
through 1.26 and newer). It loads a module once with full type information,
builds SSA and a VTA call graph, and follows untrusted data across functions
and packages to report security flaws with a source-to-sink trace. The same
pass finds production reliability bugs (network calls inside transactions,
leaked bodies, rows and goroutines), architecture violations, and
supply-chain risks: reachable vulnerabilities, risky module provenance and
dependencies that gain new privileges. It is a single binary that needs only
the Go toolchain of the project it analyzes, makes no network requests unless
the dependency audit is enabled, and writes SARIF, JSON, HTML, Markdown,
GitHub, GitLab and compact plain-text reports.

## Contents

- [Why CodexSentinel](#why-codexsentinel)
- [60-second quick start](#60-second-quick-start)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Rules](#rules)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [CI integration](#ci-integration)
- [Editors and MCP clients](#editors-and-mcp-clients)
- [golangci-lint and go/analysis](#golangci-lint-and-goanalysis)
- [Benchmarks](#benchmarks)
- [Development](#development)
- [License](#license)

## Why CodexSentinel

CodexSentinel complements `golangci-lint` and `govulncheck` rather than
replacing them: keep golangci-lint for style and general correctness, and add
CodexSentinel for the questions that need the whole program.

| Capability | CodexSentinel | golangci-lint (with gosec) | govulncheck |
| --- | --- | --- | --- |
| Taint tracking across functions and packages, with source-to-sink traces | Yes (SSA + VTA) | Per-call patterns | No |
| Go 1.24 `os.Root` and Go 1.25 `http.CrossOriginProtection` recognized as safe | Yes | No | No |
| Network I/O inside database transactions or under a mutex | Yes | No | No |
| Unclosed response bodies and rows, missing rollbacks, `defer` in loops | Yes | Partly (`bodyclose`, `sqlclosecheck`) | No |
| Excessive JSON exposure and mass assignment in APIs | Yes | No | No |
| Credentials and personal data in `slog`, `zap`, `zerolog` and `log` | Yes | No | No |
| Known vulnerabilities with call-graph reachability | Yes (opt-in, OSV and GHSA) | No | Yes |
| Capability lock file for dependencies (`.codexsentinel.caps.json`) | Yes | No | No |
| `go.mod` provenance: typosquatting, young, retracted and deprecated modules | Yes | Partly (`gomodguard`, `gomoddirectives`) | No |
| CycloneDX 1.6 SBOM with reachability-based OpenVEX | Yes | No | OpenVEX only |
| Architecture layers, import cycles and boundary type leaks | Yes | Partly (`depguard`) | No |
| Built-in language server and Model Context Protocol server | Yes | No | No |
| Style and general correctness linters | A few YAML rules | Yes, over 100 linters | No |

On the benchmark corpora CodexSentinel finds 14 of 14 seeded defects with no
false positives, against 6 of 14 for gosec; it is also slower and uses more
memory, because it builds the whole program. The corpora, numbers and the
script to reproduce them are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## 60-second quick start

Install it in one of these ways:

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
```

```bash
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
```

```bash
docker build -t codexsentinel . && docker run --rm -v "$PWD:/workspace" codexsentinel scan . --format agent --out -
```

```yaml
# .github/workflows/codexsentinel.yml, see CI integration below
- uses: Voskan/codexsentinel@v2
```

Then, in the module root:

```bash
codex-cli init --with-caps
```

writes a `.codexsentinel.yaml` tailored to the module's layout, an empty
ignore file and the capability lock file.

```bash
codex-cli scan .
```

scans the module and writes a SARIF report to `scan_reports/`.

```bash
codex-cli scan . --diff origin/main --forbid-new-suppressions --strict
```

is the pull request gate: only findings on changed lines, and a failure when
the change adds suppressions instead of fixes.

```bash
codex-cli sbom . --vex --out sbom.cdx.json --vex-out openvex.json
```

writes a CycloneDX SBOM and an OpenVEX document that marks unreachable
vulnerabilities `not_affected`.

```bash
codex-cli rules
```

```bash
codex-cli explain sql-injection
```

list the 85 rules and explain one, with a vulnerable and a safe example.

## Features

**Interprocedural taint analysis.**
- Untrusted data is tracked from sources to sinks on SSA form. Sources are HTTP requests, environment variables, command-line arguments and similar inputs. Sinks are SQL queries, commands, file paths, outbound URLs, HTML responses, redirects, template source text and Redis Lua scripts.
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

**SBOM and VEX.**
- `codex-cli sbom` writes a CycloneDX 1.6 (or SPDX 2.3) bill of materials with package URLs, `go.sum` hashes, licenses and the capabilities each dependency's reachable code uses.
- With `--vex`, known vulnerabilities are added and marked by reachability; `--vex-out` writes an OpenVEX document in which unreachable vulnerabilities are `not_affected` (`vulnerable_code_not_in_execute_path`), ready for `trivy --vex` or `grype --vex`.

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

Build from source with Go 1.24 or newer. The analyzer type-checks your code
with the Go version it was built with, so build it with the newest Go release
to analyze modules that use the latest language version; release binaries and
the container image are built that way.

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
codex-cli init                                     # write .codexsentinel.yaml for this module or workspace
codex-cli scan .                                   # SARIF report in scan_reports/
codex-cli scan ./... --format json --out report.json
codex-cli scan . --format html --out report.html
codex-cli scan . --format markdown --out report.md
codex-cli scan . --format agent --out -            # compact remediation report on stdout
codex-cli scan . --format github                   # GitHub Actions annotations and job summary
codex-cli scan . --format gitlab                   # GitLab Code Quality report
codex-cli scan . --format json --out -             # write the report to stdout
codex-cli scan . --severity high                   # only high and critical findings
codex-cli scan . --strict                          # exit code 1 when findings remain
codex-cli scan . --deps                            # dependency audit only (--severity applies)
codex-cli scan . --no-cache                        # ignore the analysis cache
codex-cli cache status                             # cache location and size
codex-cli cache clean                              # remove cached results
codex-cli sbom . > sbom.cdx.json                   # CycloneDX 1.6 SBOM
codex-cli sbom . --vex --vex-out openvex.json      # add vulnerabilities and write OpenVEX
codex-cli rules --category reliability             # list rules (table, json or markdown)
codex-cli explain sql-injection                    # description, examples and references for a rule
codex-cli lsp                                      # language server for editors (stdio)
codex-cli mcp                                      # Model Context Protocol server (stdio)
```

`codex-cli init` reads `go.mod` and the directory tree and writes a commented
`.codexsentinel.yaml`: architecture layers for directories named after common
layers (`handler`, `controller` and `api` become delivery; `service` and
`usecase` the service layer; `domain`, `entity` and `model` the domain;
`repository`, `repo`, `storage` and `adapter` the repository layer), allowed
dependencies between them, and exclusions for mocks, `gen` directories and
`*.pb.go` files when present. It also creates an empty `.codexsentinel.ignore`.
An existing configuration is kept unless `--force` is given; `--with-caps`
writes the capability lock file as well.

`codex-cli explain` accepts a rule ID or its code (`CS001`) and suggests
similar IDs for a typo. Every finding's rule can be looked up this way.

Package-level results are cached on disk and reused while a package, the
packages it imports, the configuration and the analyzer are unchanged.

The target may be a module directory, a package pattern ending in `/...`, or a
single `.go` file. Findings are reported relative to the module root.

In a go.work workspace, scanning a directory that is not itself a module, such
as the workspace directory, analyzes the workspace modules below it together, so taint
flows from one module into another are found; findings are relative to the
workspace directory and architecture layers match paths from there. Requirements
on modules of the workspace are not reported as missing from `go.sum`, and
`--deps` audits the `go.mod` of each module. `sbom` describes one module, so run
it in a module directory. `GOWORK=off` disables workspaces as it does for the
go command.

### Pull requests and legacy code

```bash
# Only findings on lines changed since origin/main (untracked files count as changed)
codex-cli scan . --diff origin/main --strict

# Record the current findings once, then report only new ones
codex-cli baseline create . --out .codexsentinel.baseline.json
codex-cli scan . --baseline .codexsentinel.baseline.json --strict

# Fail when the change adds suppressions instead of fixes
codex-cli scan . --diff origin/main --forbid-new-suppressions
```

`--forbid-new-suppressions` reports every suppression added since the `--diff`
reference (`HEAD` when none is given) as a critical
`unauthorized-suppression-added` finding and fails the scan: `//codex:ignore`,
`//nolint` and `#nosec` in Go comments, new ignore-file entries, and
configuration lines that disable rules, exclude paths or relax thresholds
(also in `.golangci.yml`). Text in string literals, tightened settings and
suppressions that only moved are not reported, and the finding cannot be
suppressed itself. CI approves a reviewed change by setting
`CODEX_ALLOW_SUPPRESSIONS=1`, for example when a security reviewer has labeled
the pull request. `suppression.forbid_new_suppressions: true` enables the
check from the configuration.

`--format agent` writes a compact plain-text report for automated
remediation: a `STATUS: PASS (0 issues)` or `STATUS: FAIL (...)` line, then one
block per finding with `ISSUE [SEVERITY] rule (CWE) at file:line:col`, `WHY`,
the data flow as `FLOW: source -> call -> sink`, `FIX` and, when a fix is
available, `PATCH` lines with the exact replacement. Output is sorted and
deterministic.

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

The [rule reference](docs/rules/README.md) has a page for every rule: what it
detects, why it matters in Go, a problematic and a safe example, CWE and OWASP
mapping, and how to configure or suppress it. SARIF reports and editor
diagnostics link to these pages. The reference is generated from the rule
catalog with `make docs-generate`, and a test fails when it is out of date.

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
| `nosql-injection` | High | CWE-943 | A05 |
| `sql-injection` | High | CWE-89 | A05 |
| `template-injection` | High | CWE-1336 | A05 |
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
`path-traversal`, `ssrf`, `xss`, `open-redirect`, `template-injection`
(untrusted text passed to `Template.Parse`) and `nosql-injection` (untrusted
text in a go-redis `Eval`, `EvalRO`, `ScriptLoad` or `NewScript` script)
findings with a trace. `nosql-injection` also covers MongoDB `$where`,
`$function` and `$accumulator` JavaScript built from request input in the
function that builds the query document.
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
| `dependency-typosquatting` | A required module is one or two characters away from a well-known module without being one (offline) |
| `gomod-local-replace` | A `replace` directive points at a local directory (offline) |
| `gomod-missing-checksum` | A direct requirement has no content hash in `go.sum` (offline) |
| `dependency-policy-denied` | A module matches `denied_prefixes` or falls outside `allowed_prefixes` (offline) |
| `dependency-young-module` | The required version was published less than `min_module_age_days` ago (module proxy) |
| `dependency-retracted` | The required version is retracted by the module's authors (module proxy) |
| `dependency-deprecated` | The module is marked deprecated in its latest `go.mod` (module proxy) |
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
| `unauthorized-suppression-added` | With `--forbid-new-suppressions`, the change adds a suppression or weakens the configuration |

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

The default YAML rules:

| Rule ID | Severity | Reported when |
| --- | --- | --- |
| `go.security.plaintext-http-request` | Medium | `http.Get` is called with an `http://` URL to a non-local host |
| `go.security.plaintext-http-request-new` | Medium | A request is built for an `http://` URL to a non-local host |
| `go.architecture.sql-in-transport-layer` | Low | A handler, API or transport package calls `*sql.DB` or `*sql.Tx` directly |
| `go.architecture.http-in-data-layer` | Low | A repository, model or storage package registers HTTP handlers |
| `go.correctness.self-assignment` | Low | An expression is assigned to itself |
| `go.style.strings-replace-all` | Info | `strings.Replace(s, old, new, -1)` can be `strings.ReplaceAll` (autofix) |
| `go.style.time-since` | Info | `time.Now().Sub(t)` can be `time.Since(t)` (autofix) |
| `go.style.bytes-equal` | Info | `bytes.Compare(a, b) == 0` can be `bytes.Equal(a, b)` (autofix) |

## Configuration

`codex-cli` looks for `.codexsentinel.yaml`, `.codexsentinel.yml`,
`codex.yaml` or `.codex.yml` in the root of the scanned module (or go.work
workspace), then in its parent directories up to the repository root (the
directory with `.git`), and finally in the current directory. Pass `--config`
to use another file. Relative paths in `rules.rule_paths` and
`rules.rule_files` are resolved against the directory of the configuration
file, so a scan gives the same result from any working directory. Unknown keys
and invalid values are rejected. The defaults are:

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
  check_provenance: true         # typosquatting and policy offline; proxy lookups with enable
  check_hygiene: true            # local replace directives and go.sum checksums
  min_module_age_days: 7         # 0 disables the age check
  allowed_prefixes: []           # when set, only these module prefixes are allowed
  denied_prefixes: []
suppression:
  ignore_file: .codexsentinel.ignore
  enable_inline_ignore: true
  require_ignore_reason: false
  min_confidence: 0.5            # findings below this confidence are dropped
  forbid_new_suppressions: false # like --forbid-new-suppressions
report:
  formats: [sarif]               # every listed format is written when --format is not given
  output_dir: scan_reports
  fail_on_severity: ""           # e.g. high: exit 1 on high or critical findings
```

Without `--format`, `scan` writes one report per entry of `report.formats`
into `report.output_dir`; `github` writes annotations to standard output.
`--format` overrides the list. `--out` names a single report file, so it needs
exactly one format.

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

### GitHub Action

The action installs a release binary (verified against the release's
`checksums.txt`, or built from source with `version: source`), scans the
module and, with the default `github` format, annotates the findings' lines in
the pull request and writes a job summary. Annotations work in private
repositories without code scanning.

```yaml
name: CodexSentinel
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Voskan/codexsentinel@v2
        with:
          severity: medium
          diff: ${{ github.event_name == 'pull_request' && format('origin/{0}', github.base_ref) || '' }}
          forbid-new-suppressions: ${{ github.event_name == 'pull_request' }}
```

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `latest` | Release tag, `latest`, or `source` to build the action's revision (needs Go) |
| `path` | `.` | Module directory |
| `severity` | `medium` | Minimum severity |
| `diff` | | Report only lines changed since this reference |
| `strict` | `true` | Fail the step when findings remain |
| `forbid-new-suppressions` | `false` | Fail when the change adds suppressions |
| `caps-verify` | `true` | Run `caps verify` when `.codexsentinel.caps.json` exists |
| `format` | `github` | `github`, `gitlab`, `sarif`, `json`, `markdown`, `html` or `agent` |
| `output` | | Report file for formats other than `github` |
| `args` | | Extra `scan` arguments |

`--format github` prints GitHub workflow commands (`::error` for critical and
high, `::warning` for medium, `::notice` for low findings) to stdout and
appends a Markdown summary to `$GITHUB_STEP_SUMMARY`; `--github-summary FILE`
writes that summary for any format. GitHub shows at most 10 annotations of
each level per step and 50 per job, and the summary lists the 200 most severe
findings.

With GitHub Advanced Security, upload SARIF to code scanning instead:

```yaml
      - run: codex-cli scan . --strict --severity high --format sarif --out results.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab

`--format gitlab` writes a Code Quality report that merge request widgets
display on every GitLab tier, including Free:

```yaml
codexsentinel:
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
    - codex-cli scan . --format gitlab --out gl-code-quality-report.json --strict
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

Severities map to `blocker` (critical), `critical` (high), `major` (medium),
`minor` (low) and `info`.

### pre-commit

```yaml
repos:
  - repo: https://github.com/Voskan/codexsentinel
    rev: v2.0.0
    hooks:
      - id: codexsentinel-scan   # codex-cli scan . --strict --severity high
      - id: codexsentinel-caps   # codex-cli caps verify . when go.mod, go.sum or the lock file change
```

For pull requests, scan only the changed lines with
`codex-cli scan . --diff origin/${{ github.base_ref }} --strict`. This needs
`fetch-depth: 0`, as above, so the base branch is available.

This repository runs `go vet`, the race-enabled tests, a self-scan with
`--strict --severity low` and `caps verify` on every push to `main` and every pull request
([.github/workflows/go.yml](.github/workflows/go.yml)).

## Editors and MCP clients

`codex-cli lsp` is a Language Server Protocol server on stdio. Editors show
findings as diagnostics when a Go file is opened or saved, with CWE, OWASP and
the data flow in the hover text. Code actions apply a finding's fix or append
`//codex:ignore <rule> -- TODO: document reason` to the line. The suppression
action is not offered when `suppression.forbid_new_suppressions` is set.
It runs next to gopls; neither replaces the other.

Neovim (0.11 or newer):

```lua
vim.lsp.config("codexsentinel", { cmd = { "codex-cli", "lsp" }, filetypes = { "go" }, root_markers = { "go.mod" } })
vim.lsp.enable("codexsentinel")
```

Helix (`languages.toml`):

```toml
[language-server.codexsentinel]
command = "codex-cli"
args = ["lsp"]

[[language]]
name = "go"
language-servers = ["gopls", "codexsentinel"]
```

VS Code and Zed start additional language servers through extensions: with a
generic language client extension, set the server command to `codex-cli lsp`
and the document language to `go`.

`codex-cli mcp` is a Model Context Protocol server on stdio with five tools:

| Tool | Arguments | Result |
| --- | --- | --- |
| `scan_path` | `path`, optional `severity`, `deps_only` | Findings in the compact `agent` format |
| `scan_diff` | `path`, `git_ref`, optional `forbid_new_suppressions` | Findings on lines changed since `git_ref` |
| `verify_capabilities` | `path`, optional `lockfile` | Capability escalations against the lock file |
| `explain_rule` | `rule` (ID or code) | The rule's explanation and examples |
| `list_rules` | optional `category` | The rule catalog |

```json
{ "mcpServers": { "codexsentinel": { "command": "codex-cli", "args": ["mcp"] } } }
```

Both servers write only protocol messages to stdout. Warnings go to stderr,
and `--log-file` records detailed logs.

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

## Benchmarks

On a four-layer service with 14 known defects, CodexSentinel reports all 14
and nothing else, and on the same service written safely it reports nothing;
see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for the corpora, the comparison
with gosec and govulncheck, timings, and how to reproduce them.

## Development

```bash
make build      # build/codex-cli
make test       # go test -race ./...
make docs-generate  # regenerate docs/rules after changing a rule
go vet ./...
```

At the time of writing, `go test -cover ./...` reports 78.9% total statement
coverage. See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture overview
and how to write and test rules. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
