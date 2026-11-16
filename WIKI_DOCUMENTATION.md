# CodexSentinel Documentation

This page describes how each analysis works and documents every configuration
key, suppression mechanism and report format. For a first run, start with the
[Quick Start](WIKI_QUICK_START.md).

## Contents

- [Command line](#command-line)
- [How a scan works](#how-a-scan-works)
- [Security rules](#security-rules)
- [Taint analysis](#taint-analysis)
- [Dependency analysis](#dependency-analysis)
- [Capability lock file](#capability-lock-file)
- [Architecture analysis](#architecture-analysis)
- [Metrics](#metrics)
- [YAML rules](#yaml-rules)
- [Suppressions](#suppressions)
- [Baselines and diff mode](#baselines-and-diff-mode)
- [Reports](#reports)
- [Configuration reference](#configuration-reference)

## Command line

| Command | Purpose |
| --- | --- |
| `codex-cli scan [path]` | Analyze a module, a package pattern (`./...`) or a single `.go` file |
| `codex-cli baseline create [path] --out FILE` | Record the current findings in a baseline file |
| `codex-cli caps inspect [path]` | Print the capabilities each dependency uses, with a call path as evidence |
| `codex-cli caps lock [path] --out FILE` | Write the capability lock file (default `.codexsentinel.caps.json`) |
| `codex-cli caps verify [path] --lockfile FILE` | Exit with code 1 when a dependency gained capabilities |
| `codex-cli mark FILE[:LINE] --rule ID --reason TEXT` | Add an entry to the ignore file |
| `codex-cli version` | Print version, commit, build date and Go version |

`scan` flags:

| Flag | Meaning |
| --- | --- |
| `-f, --format` | `sarif` (default), `json`, `html` or `markdown` |
| `-o, --out` | Report path; `-` writes the report to stdout. Default: `report.output_dir` (`scan_reports/`) |
| `--severity` | Keep findings at or above `low`, `medium`, `high` or `critical` |
| `--strict` | Exit with code 1 when findings remain after filtering |
| `--diff REF` | Report only findings on lines changed since the git reference |
| `--baseline FILE` | Hide findings recorded in the baseline |
| `--fix` | Apply the suggested fixes of the reported findings to the source files |
| `--deps` | Run only the dependency audit |
| `--config FILE` | Use this configuration file |
| `--ignore-file FILE` | Use this ignore file instead of `suppression.ignore_file` |

Exit code 0 means the scan completed without failing findings. Exit code 1
means one of the following:
- Findings remain with `--strict` or with `report.fail_on_severity` set.
- `caps verify` found escalations.
- The scan failed. In this case an `error:` line is printed to stderr.

## How a scan works

1. **Load.** `go/packages` loads the target packages with syntax and type information (`analyzer/workspace`).
   - Files under `scan.excluded_paths`, generated files and test files are excluded from the analysis unless enabled. Excluded files still take part in type checking and SSA construction.
2. **Package rules.** The built-in rules and the YAML rules run on every package, in parallel up to `scan.concurrency`.
3. **Whole-program analyses.** These share one SSA program and one VTA call graph (`analyzer/ssa`):
   - taint analysis
   - dependency reachability
   - capability check
   - architecture checks
   - metrics and dead code
4. **Post-processing** (`analyzer/engine`):
   1. Rule selection and severity overrides.
   2. The `suppression.min_confidence` threshold.
   3. File paths relative to the module root.
   4. Inline directives.
   5. The ignore file.
   6. Deduplication by file, line and rule, preferring the finding with the longer trace and then the higher confidence.
   7. Fingerprints.
   8. Ordering by severity, file, line and rule.

## Security rules

The built-in rules live in `analyzer/rules/builtin`. They resolve calls
through type information, so `import sq "database/sql"` is recognized and
a local function called `Query` is not. The README lists every rule with its
severity, CWE and OWASP category. Notable behavior:

| Area | Rules | Notes |
| --- | --- | --- |
| Injection | `sql-injection`, `command-injection`, `xss` | Report queries, commands and HTML built from non-constant data. The taint engine adds interprocedural flows. Supports `database/sql`, sqlx, pgx and gorm. |
| Files | `path-traversal`, `archive-zip-slip`, `archive-decompression-bomb`, `insecure-file-permissions` | Access through `*os.Root` (Go 1.24) is confined and never reported. `filepath.Join` with request input is reported with a hint to use `os.OpenRoot`. |
| Web | `csrf-missing-protection`, `cors-wildcard-credentials`, `websocket-origin-bypass`, `cookie-*`, `debug-endpoint-exposed` | `csrf-missing-protection` reports state-changing routes that use cookie sessions without cross-origin protection. These count as protection: `http.NewCrossOriginProtection` (Go 1.25), gorilla/csrf, justinas/nosurf, gin-csrf, the fiber CSRF middleware, and echo's `middleware.CSRF`. |
| Denial of service | `http-server-missing-timeout`, `http-unbounded-body-read`, `untrusted-slice-allocation`, `http-client-unsafe`, `graphql-unbounded-query`, `context-propagation-missing` | `http.MaxBytesReader` and `io.LimitReader` bound a body read. |
| Cryptography | `crypto-weak-hash`, `crypto-weak-cipher`, `crypto-weak-rand`, `crypto-weak-rsa`, `tls-insecure-config` | `tls-insecure-config` provides fixes for `InsecureSkipVerify` and old `MinVersion` values. |
| Authentication | `jwt-*`, `auth-hardcoded-credential`, `auth-non-constant-time-compare`, `hardcoded-secret` | Covers golang-jwt and similar libraries. Secrets combine provider-specific patterns with an entropy check. |
| Logging | `sensitive-data-in-logs` | Detailed below. |
| Deserialization | `unsafe-gob-decode` | Reports gob decoding of request bodies. |
| Access control | `idor-unscoped-mutation` | Reports updates and deletes keyed only by a request parameter, without an owner or tenant condition. |

### Sensitive data in logs

`sensitive-data-in-logs` inspects the arguments of these loggers:
- `log/slog`: functions, `Logger` methods and `slog.Attr` constructors
- `go.uber.org/zap`: `Logger` and `SugaredLogger`, plus field constructors such as `zap.String` and `zap.Any`
- `github.com/rs/zerolog`: event field methods
- the standard `log` package

A value is reported when its key, variable or field name denotes a credential
or personal data (password, token, secret, API key, card number, SSN, and so
on), or when it is a struct containing such fields.

A type that controls its own log representation is not reported:
- `slog.LogValuer`
- `zapcore.ObjectMarshaler`
- `zerolog.LogObjectMarshaler`

Implementing one of these is the recommended fix.

## Taint analysis

The taint engine (`analyzer/flow`) runs on SSA. With
`taint.interprocedural: true` (the default) it summarizes each function, so
taint crosses:
- calls, return values and pointer arguments
- closures and struct fields
- interface and function-value calls, resolved by the VTA call graph

### Sources

| Tag | Sources |
| --- | --- |
| `http` | `net/http.Request` methods and fields (`FormValue`, `PathValue`, `URL`, `Header`, `Body`, `Cookie`, ...), `url.Values.Get`, gin, echo and fiber context accessors and binders, chi `URLParam`, gorilla/mux `Vars` |
| `cli` | `os.Args`, `os.Stdin`, `fmt.Scan*` (confidence 0.7) |
| `env` | `os.Getenv`, `os.LookupEnv` (confidence 0.6) |

`cli` and `env` input is controlled by whoever runs the program. It is not
reported for `path-traversal`, because opening a file the operator named is
the normal behavior of a command-line tool.

### Sinks

| Category | Severity | Sinks |
| --- | --- | --- |
| `sql-injection` | High | `database/sql` DB/Tx/Conn queries, sqlx, pgx v4/v5 and pgxpool, gorm raw and clause methods |
| `command-injection` | Critical | `exec.Command`, `exec.CommandContext`, `syscall.Exec`, `syscall.ForkExec`, `os.StartProcess` |
| `path-traversal` | High | `os` file functions, `io/ioutil`, `http.ServeFile`, `http.Dir` |
| `ssrf` | High | `http.Get`/`Post`/`Head`/`PostForm`, `http.NewRequest[WithContext]`, `http.Client` methods, `net.Dial[Timeout]` |
| `xss` | High | `http.ResponseWriter.Write`, `fmt.Fprint*` and `io.WriteString` to a response, `text/template` execution to a response, `html/template.HTML` and the other trusted-type conversions |
| `open-redirect` | Medium | `http.Redirect` |

### Sanitizers

- **All categories.** Numeric and boolean parsing (`strconv`), UUID parsing,
  `netip.ParseAddr`, hashing and hex encoding.
- **Specific categories.**
  - `html.EscapeString` and the template escapers clear `xss`.
  - `filepath.Base` clears `path-traversal`.
  - `url.QueryEscape` and `url.PathEscape` clear `xss`, `sql-injection`, `command-injection` and `path-traversal`.
  - `pq.QuoteIdentifier` and `pgx.Identifier.Sanitize` clear `sql-injection`.
  - bluemonday policies clear `xss`.

### Custom specifications

```yaml
taint:
  custom_sources:
    - package: github.com/acme/web
      receiver: Context        # omit for package-level functions
      function: Param
      tags: [http]
  custom_sinks:
    - package: github.com/acme/store
      function: RawQuery
      check_args: [0]          # argument indexes, not counting the receiver
      category: sql-injection
  custom_sanitizers:
    - package: github.com/acme/security
      function: CleanPath
      categories: [path-traversal]
```

Every taint finding has a `trace`. Each step has a location, a message and a
kind: `source`, `param`, `call`, `return`, `propagation` or `sink`. In SARIF
the trace is a `codeFlows` thread flow.

## Dependency analysis

Enable it with `dependencies.enable: true`, or run `codex-cli scan --deps`.
It reads `go.mod` and checks the following.

- **Vulnerabilities.**
  - Every required module, plus the standard library version taken from the `go` and `toolchain` directives, is queried in OSV and the Go vulnerability database.
  - GitHub Security Advisories are queried as well when `GITHUB_TOKEN` is set.
  - The results are reported as `dependency-vulnerability`.
- **Reachability** (`check_reachability`).
  - When the advisory names affected symbols, the call graph decides whether the module's code can reach them.
  - Each finding carries `reachable: true|false`. Unreachable vulnerabilities are reported as Low.
- **Licenses** (`check_licenses`).
  - License files of the modules (from `vendor/` or `$GOMODCACHE`) are classified, then checked against `allow_licenses` and `deny_licenses`.
  - Violations are reported as `license-denied`.

Vendored modules are also scanned for high-entropy strings, which are
reported as `high-entropy-string`. Network failures are reported as a warning,
and the rest of the scan completes.

## Capability lock file

`codex-cli caps inspect` attributes privileged operations to the dependency
module whose code performs them, starting from code reachable in the call
graph:

| Capability | Evidence |
| --- | --- |
| `CAP_FS_READ`, `CAP_FS_WRITE` | `os` file functions |
| `CAP_NETWORK` | `net` dialers and listeners, HTTP clients and servers |
| `CAP_ENV` | `os.Getenv`, `os.LookupEnv`, `os.Environ`, `os.ExpandEnv` |
| `CAP_EXEC` | `exec.Command`, `exec.CommandContext`, `Cmd.Start`/`Run`/`Output`/`CombinedOutput`, `os.StartProcess`, `syscall.Exec`/`ForkExec` |
| `CAP_REFLECT`, `CAP_UNSAFE`, `CAP_CGO`, `CAP_PLUGIN` | Importing `reflect`, `unsafe`, `runtime/cgo` or `plugin`, and calling `plugin.Open` |

Calls into the standard library are followed through static calls only, up to
a fixed depth. Package initializers are not attributed to the importing
module.

`caps lock` writes the result to `.codexsentinel.caps.json`. Commit this file.
`caps verify` then fails when a dependency upgrade adds a capability. With
`dependencies.check_capabilities: true`, `scan` reports the same escalations
as `supply-chain-capability-escalation` findings. An escalation is Critical
when the module gains exec, cgo or plugin access, or when it gains
environment or network access and now has both. Otherwise it is High.

## Architecture analysis

| Rule | Behavior |
| --- | --- |
| `arch-layer-violation` | Packages are assigned to layers by path segments or globs (`architecture.layers`). An import of a layer outside `allowed_deps` is reported. |
| `arch-import-cycle` | Reports import cycles between packages of the module. |
| `arch-god-struct` | Reports a struct with more than `god_struct_max_methods` methods, or with more than `god_struct_max_fields` fields and more than two methods. Plain data records with many fields are not reported. |
| `arch-boundary-type-leak` | Reports exported functions and fields of outer layers whose signatures expose types of layers they should hide. For example, a handler returning a repository type. |

Without configured layers, a default Clean Architecture layout applies:

| Layer | Path segments | May depend on |
| --- | --- | --- |
| delivery | `handler`, `controller`, `delivery`, `transport`, `api` | usecase, service, domain |
| usecase | `usecase`, `application` | domain, port |
| service | `service` | usecase, domain, repository, port |
| port | `port` | domain |
| repository | `repository`, `repo`, `adapter`, `store`, `db`, `infra` | domain, port |
| domain | `domain`, `entity`, `model` | nothing |

A segment also matches its plural (`handler` matches `handlers`).

```yaml
architecture:
  layers:
    transport: [internal/http/*]
    app: [internal/app]
    storage: [internal/postgres]
  allowed_deps:
    transport: [app]
    app: [storage]
    storage: []
```

## Metrics

| Rule | Default | Behavior |
| --- | --- | --- |
| `high-complexity` | 15 | Cyclomatic complexity, counted like gocyclo: `if`, loops, non-default `case` and `select` clauses, `&&`, `\|\|` |
| `large-function` | 80 lines | Lines of the function body |
| `large-file` | 600 lines | Lines of the file |
| `code-duplication` | 10 lines | Function bodies that are identical after normalization. Reported once per group, naming the other copies. |
| `global-variable` | on | Package variables written outside `init`, or maps, slices and channels that start empty. Exempt: constants, sentinel errors, compiled regexps, `embed.FS`, `sync` values, templates, and variables declared in one `var (...)` block with a `sync.Mutex`, `sync.RWMutex` or `sync.Once`. |
| `dead-code` | on | Functions not reachable from any entry point in the call graph: `main`, `init`, exported API of library packages, tests |

A threshold of 0 disables the check.

## YAML rules

YAML rules are loaded from `assets/rules` in the working directory, from every
directory in `rules.rule_paths` and from every file in `rules.rule_files`.

```yaml
id: go.security.plaintext-http-request
title: Plaintext HTTP request
category: security
severity: MEDIUM
cwe: CWE-319
description: A request is sent over unencrypted HTTP.
match:
  pattern: "http.Get($URL)"
  filters:
    - type: regex
      var: $URL
      include: ['^"http://']
      exclude: ['^"http://(localhost|127\.0\.0\.1|\[::1\])([:/"]|$)']
suggestion: Use an https:// URL.
```

- `pattern` is Go code with metavariables. `$X` matches any expression, a
  repeated `$X` must match the same expression, and `$...` matches any number
  of call arguments.
- Package names match renamed imports.
- `not_pattern` excludes matches that contain another pattern.
- Filters restrict a metavariable:
  - `type` (`include: [net/http.ResponseWriter]`)
  - `non_const`
  - `regex` (`include` / `exclude` regular expressions over the matched source text)
- `fix` is a replacement template that reuses the metavariables. `--fix`
  applies it.

See [assets/rules](assets/rules) for working examples.

## Suppressions

### Inline directives

```go
//codex:ignore sql-injection -- the table name comes from a fixed allow list
rows, err := db.Query("SELECT * FROM " + table)

x := risky() //codex:ignore ssrf,xss -- reviewed

//codex:ignore global-variable -- process-wide cache, guarded by cacheMu
var cache = map[string]string{}
```

- A trailing comment covers its own line.
- A comment on its own line covers the next line.
- A doc comment covers the whole declaration it documents.
- Rule IDs accept globs.
- No rule ID, or `*`, suppresses every rule.
- With `suppression.require_ignore_reason: true`, a directive without
  `-- reason` is reported as `ignore-missing-reason`.
- `suppression.enable_inline_ignore: false` turns directives off.

### Ignore file

`.codexsentinel.ignore` holds one entry per line, relative to the module
root. `#` starts a comment.

```text
# Paths: ignore every rule
**/*.pb.go
/vendor/
internal/generated/

# Paths with rules
internal/legacy/** sql-injection,xss

# A single line
cmd/tool/main.go:42 path-traversal

# A rule everywhere
context-propagation-missing
```

Path patterns:
- `**` matches any number of directories.
- A leading `/` anchors the pattern at the root.
- A trailing `/` matches a directory and everything below it.
- `# text` after an entry is kept as its comment.

## Baselines and diff mode

**Baselines.** `codex-cli baseline create` writes `.codexsentinel.baseline.json`.
- Each entry has a fingerprint, the rule ID, the file, the enclosing function and a timestamp.
- The fingerprint hashes the rule, the file, the enclosing declaration, the trimmed source line and its occurrence index. It therefore survives code being inserted above the finding.
- `scan --baseline FILE` drops findings whose fingerprints are recorded.

**Diff mode.** `scan --diff REF` analyzes the whole program, so interprocedural
flows stay correct, but reports only findings on lines changed between `REF`
and the working tree.
- Untracked files count as fully changed.
- Dependency findings on `go.mod` are kept when `go.mod` or `go.sum` changed.

## Reports

| Format | Contents |
| --- | --- |
| SARIF 2.1.0 | Rules with CWE/OWASP tags and `security-severity`, results with `codeFlows`, `fixes` and `partialFingerprints.primaryLocationLineHash`, git metadata |
| JSON | `summary` (counts per severity and category), `issues`, `generated_at`, `git` |
| HTML | A single page with summary cards, findings by category and per-finding details including traces. Icons load from cdnjs. |
| Markdown | Repository information, summary, tables per severity, details and remediation |

## Configuration reference

The configuration file is found in the current directory as
`.codexsentinel.yaml`, `.codexsentinel.yml`, `codex.yaml` or `.codex.yml`, in
that order. It can also be given with `--config`. Unknown keys and invalid
values are errors. Omitted keys keep their defaults.

| Key | Default | Meaning |
| --- | --- | --- |
| `version` | `1` | Schema version |
| `scan.include_tests` | `false` | Analyze `_test.go` files |
| `scan.include_vendor` | `false` | Analyze `vendor/` |
| `scan.include_generated` | `false` | Analyze files marked `// Code generated ... DO NOT EDIT.` |
| `scan.excluded_paths` | `[vendor, testdata, node_modules, .git]` | Paths or globs excluded from analysis |
| `scan.max_file_size_bytes` | `10485760` | Larger files are skipped |
| `scan.supported_extensions` | `[.go]` | Source file extensions |
| `scan.concurrency` | `0` | Parallel package workers; 0 uses all CPUs |
| `rules.enabled` | `["*"]` | Rule IDs or globs to run |
| `rules.disabled` | `[]` | Rule IDs or globs to skip |
| `rules.severity_overrides` | `{}` | Rule ID to `low`, `medium`, `high` or `critical` |
| `rules.rule_paths`, `rules.rule_files` | `[]` | Extra YAML rule directories and files |
| `taint.enable` | `true` | Run the taint engine |
| `taint.interprocedural` | `true` | Follow taint across functions |
| `taint.custom_sources`, `custom_sinks`, `custom_sanitizers` | `[]` | See [Custom specifications](#custom-specifications) |
| `architecture.enable` | `true` | Run architecture checks |
| `architecture.layers`, `allowed_deps` | `{}` | Layer model; empty uses the default layout |
| `architecture.check_cycles`, `check_god_structs`, `check_boundaries` | `true` | Individual checks |
| `architecture.god_struct_max_methods`, `god_struct_max_fields` | `15`, `20` | God struct thresholds |
| `metrics.enable` | `true` | Run metrics |
| `metrics.max_cyclomatic`, `max_function_loc`, `max_file_loc`, `min_duplicate_loc` | `15`, `80`, `600`, `10` | Thresholds; 0 disables |
| `metrics.enable_duplication`, `enable_dead_code`, `enable_globals` | `true` | Individual checks |
| `dependencies.enable` | `false` | Run the dependency audit during `scan` |
| `dependencies.check_vulnerabilities`, `check_reachability`, `check_licenses` | `true` | Individual checks |
| `dependencies.check_capabilities` | `false` | Verify the capability lock file during `scan` |
| `dependencies.capability_lockfile` | `.codexsentinel.caps.json` | Lock file path, relative to the module root |
| `dependencies.allow_licenses`, `deny_licenses` | see README | SPDX identifiers |
| `suppression.ignore_file` | `.codexsentinel.ignore` | Ignore file, relative to the module root |
| `suppression.enable_inline_ignore` | `true` | Honor `//codex:ignore` |
| `suppression.require_ignore_reason` | `false` | Report directives without a reason |
| `suppression.min_confidence` | `0.5` | Drop findings below this confidence |
| `report.formats` | `[sarif]` | Default report format |
| `report.output_dir` | `scan_reports` | Default report directory |
| `report.fail_on_severity` | `""` | Exit with code 1 when findings at or above this severity remain |
