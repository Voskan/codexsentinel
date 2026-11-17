# CodexSentinel Documentation

This page describes how each analysis works and documents every configuration
key, suppression mechanism and report format. For a first run, start with the
[Quick Start](WIKI_QUICK_START.md).

## Contents

- [Command line](#command-line)
- [How a scan works](#how-a-scan-works)
- [Analysis cache](#analysis-cache)
- [Security rules](#security-rules)
- [Reliability rules](#reliability-rules)
- [Taint analysis](#taint-analysis)
- [Dependency analysis](#dependency-analysis)
- [Capability lock file](#capability-lock-file)
- [SBOM and VEX](#sbom-and-vex)
- [Architecture analysis](#architecture-analysis)
- [Metrics](#metrics)
- [YAML rules](#yaml-rules)
- [Suppressions](#suppressions)
- [Baselines and diff mode](#baselines-and-diff-mode)
- [Reports](#reports)
- [Language server and MCP server](#language-server-and-mcp-server)
- [Configuration reference](#configuration-reference)

## Command line

| Command | Purpose |
| --- | --- |
| `codex-cli init [path] [--force] [--with-caps]` | Write a `.codexsentinel.yaml` with the layers, libraries and generated code found in the module, and an empty ignore file |
| `codex-cli rules [--category C] [--severity S] [--format table\|json\|markdown]` | List the rule catalog: ID, code, severity, category, CWE and OWASP category |
| `codex-cli explain RULE` | Print a rule's explanation (also in the [rule reference](docs/rules/README.md)), a vulnerable and a fixed example, references and how to suppress it; `RULE` is an ID or a code such as `CS001` |
| `codex-cli scan [path]` | Analyze a module, a package pattern (`./...`) or a single `.go` file |
| `codex-cli baseline create [path] --out FILE` | Record the current findings in a baseline file |
| `codex-cli caps inspect [path]` | Print the capabilities each dependency uses, with a call path as evidence |
| `codex-cli caps lock [path] --out FILE` | Write the capability lock file (default `.codexsentinel.caps.json`) |
| `codex-cli caps verify [path] --lockfile FILE` | Exit with code 1 when a dependency gained capabilities |
| `codex-cli cache status` | Print the cache directory, the number of entries and their size |
| `codex-cli cache clean` | Remove every cache entry |
| `codex-cli sbom [path]` | Write a CycloneDX 1.6 or SPDX 2.3 SBOM, optionally with VEX data (see [SBOM and VEX](#sbom-and-vex)) |
| `codex-cli mark FILE[:LINE] --rule ID --reason TEXT` | Add an entry to the ignore file |
| `codex-cli lsp [--log-file F] [--debounce D]` | Language Server Protocol server on stdio (see [Language server and MCP server](#language-server-and-mcp-server)) |
| `codex-cli mcp [--log-file F]` | Model Context Protocol server on stdio |
| `codex-cli version` | Print version, commit, build date and Go version |

`scan` flags:

| Flag | Meaning |
| --- | --- |
| `-f, --format` | `sarif`, `json`, `html`, `markdown`, `agent`, `github` or `gitlab`. Default: every format in `report.formats` (`sarif`) |
| `-o, --out` | Report path for a single format; `-` writes the report to stdout. Default: the format's file in `report.output_dir` (`scan_reports/`) |
| `--severity` | Keep findings at or above `low`, `medium`, `high` or `critical` |
| `--strict` | Exit with code 1 when findings remain after filtering |
| `--diff REF` | Report only findings on lines changed since the git reference |
| `--baseline FILE` | Hide findings recorded in the baseline |
| `--forbid-new-suppressions` | Fail with critical `unauthorized-suppression-added` findings when the changes since `--diff` (default `HEAD`) add suppressions; `CODEX_ALLOW_SUPPRESSIONS=1` approves them (see [Suppression policy in CI](#suppression-policy-in-ci)) |
| `--fix` | Apply the suggested fixes of the reported findings to the source files |
| `--deps` | Run only the dependency audit; `--severity` applies to its findings |
| `--config FILE` | Use this configuration file |
| `--ignore-file FILE` | Use this ignore file instead of `suppression.ignore_file` |
| `--no-cache` | Do not read or write the analysis cache |
| `--github-summary FILE` | Append a Markdown job summary to FILE (with `--format github`, `$GITHUB_STEP_SUMMARY` by default) |

Exit code 0 means the scan completed without failing findings. Exit code 1
means one of the following:
- Findings remain with `--strict` or with `report.fail_on_severity` set.
- `caps verify` found escalations.
- The scan failed. In this case an `error:` line is printed to stderr.

## How a scan works

```text
Workspace: go/packages with syntax and type information
  |-- package rules: built-in, YAML, per-file metrics          (cached per package)
  `-- SSA program + VTA call graph
        `-- interprocedural taint, dependency reachability, capabilities,
            architecture, duplication, mutable globals, dead code
-> post-processing: rule selection, confidence, suppressions, dedup, fingerprints, order
-> --baseline, --diff and --severity filters
-> report: sarif, json, html, markdown, agent, github or gitlab
```

1. **Load.** `go/packages` loads the target packages with syntax and type information (`analyzer/workspace`).
   - A target outside any module but inside a go.work workspace loads every workspace module below it as one program; see [Go workspaces](#go-workspaces).
   - Files under `scan.excluded_paths`, generated files and test files are excluded from the analysis unless enabled. Excluded files still take part in type checking and SSA construction.
2. **Package rules.** The built-in rules, the YAML rules and the per-file metrics (complexity, function and file size) run on every package, in parallel up to `scan.concurrency`. Their results are cached; see [Analysis cache](#analysis-cache).
3. **Whole-program analyses.** These share one SSA program and one VTA call graph (`analyzer/ssa`):
   - taint analysis
   - dependency reachability
   - capability check
   - architecture checks
   - duplication, mutable globals and dead code
4. **Post-processing** (`analyzer/engine`):
   1. Rule selection and severity overrides.
   2. The `suppression.min_confidence` threshold.
   3. File paths relative to the module root (the workspace directory for a go.work scan).
   4. Inline directives.
   5. The ignore file.
   6. Deduplication by file, line and rule, preferring the finding with the longer trace and then the higher confidence.
   7. Fingerprints.
   8. Ordering by severity, file, line and rule.

### Go workspaces

When the scanned directory is not inside a module but is governed by a
`go.work` file (as `go env GOWORK` reports it), `codex-cli scan` loads every
module of the workspace located below that directory, with one SSA program
and call graph:

- taint flows across modules are reported, for example request input in
  `svc/api` that reaches a query in `lib`;
- findings, traces and architecture layer paths are relative to the
  workspace directory;
- requirements on workspace modules are left out of the `go.sum`, typosquatting,
  policy and vulnerability checks, because the go command builds them from
  their directories;
- `--deps`, the dependency audit and `go.mod` hygiene run on the `go.mod` of
  each module;
- the configuration file and capability lock file are read from the
  workspace directory;
- `codex-cli init` combines the requirements of all modules; `codex-cli sbom`
  describes a single module and lists the module directories when run on the
  workspace.

Scanning one module of the workspace analyzes that module only, with the other
workspace modules as dependencies. This includes a module in the workspace
directory itself (`use .`): as with `go list ./...`, its scan does not include
the nested modules. `GOWORK=off` disables workspaces.

## Analysis cache

The results of step 2 are stored per package in a disk cache, so a repeated
scan only re-analyzes packages that changed. The key of a package is a
SHA-256 hash of:
- the analyzer build: the release version and commit, or a hash of the
  executable for development builds;
- the configuration, without cache, concurrency and report settings, and the
  definitions of the YAML rules in use;
- the package ID and the name and content of every compiled file, and which
  files are analyzed;
- a digest of every imported package, applied recursively. A module from the
  module cache is identified by its version. A standard library package is
  identified by its file names, sizes and modification times. A package of
  the main module or a replaced module is identified by its type-checked API:
  declarations, types, struct fields, methods and constant values.

Changing a function body therefore re-analyzes only that package, while
changing a struct field also re-analyzes the packages that import it.
Whole-program analyses (taint, dependencies, capabilities, architecture,
duplication, globals and dead code) always run. Loading and type checking
the packages is not cached either, so the saving grows with the number of
rules and packages.

Entries are stored as `<dir>/<ab>/<key>.json.gz` and written atomically, so
parallel scans can share a directory. The directory is `scan.cache_dir`,
otherwise `$CODEXSENTINEL_CACHE_DIR`, otherwise `codexsentinel/cache-v1` in the
user cache directory (`~/Library/Caches` on macOS, `$XDG_CACHE_HOME` or
`~/.cache` on Linux). Set `scan.enable_cache: false` or pass `--no-cache` to
turn the cache off.

## Security rules

The built-in rules live in `analyzer/rules/builtin`. They resolve calls
through type information, so `import sq "database/sql"` is recognized and
a local function called `Query` is not. The README lists every rule with its
severity, CWE and OWASP category. Notable behavior:

| Area | Rules | Notes |
| --- | --- | --- |
| Injection | `sql-injection`, `command-injection`, `xss`, `template-injection`, `nosql-injection` | Report queries, commands and HTML built from non-constant data. The taint engine adds interprocedural flows. Supports `database/sql`, sqlx, pgx and gorm. `template-injection` reports untrusted text parsed as a template; `nosql-injection` reports go-redis Lua scripts and MongoDB `$where`, `$function` and `$accumulator` JavaScript built from request input. |
| Files | `path-traversal`, `archive-zip-slip`, `archive-decompression-bomb`, `insecure-file-permissions` | Access through `*os.Root` (Go 1.24) is confined and never reported. `filepath.Join` with request input is reported with a hint to use `os.OpenRoot`. |
| Web | `csrf-missing-protection`, `cors-wildcard-credentials`, `websocket-origin-bypass`, `cookie-*`, `debug-endpoint-exposed` | `csrf-missing-protection` reports state-changing routes that use cookie sessions without cross-origin protection. These count as protection: `http.NewCrossOriginProtection` (Go 1.25), gorilla/csrf, justinas/nosurf, gin-csrf, the fiber CSRF middleware, and echo's `middleware.CSRF`. |
| gRPC | `grpc-insecure-credentials`, `grpc-server-missing-limits` | `insecure.NewCredentials()` and `grpc.WithInsecure()` are not reported when every dial target in the function is a constant loopback, `bufnet` or Unix socket address. `grpc.NewServer` is reported when its options set neither `MaxConcurrentStreams` nor an interceptor, or allow messages over 64 MiB; options built in another function are not judged. |
| Outbound requests | `ssrf`, `ssrf-missing-ip-guard` | `ssrf-missing-ip-guard` reports an `http.Transport` without an IP-checking dialer (`net.Dialer.Control`) when a client using it sends requests to URLs without a constant host, which DNS rebinding can point at `169.254.169.254` and other internal addresses. A custom `DialContext` other than a plain `net.Dialer` counts as a guard. |
| Denial of service | `http-server-missing-timeout`, `http-unbounded-body-read`, `untrusted-slice-allocation`, `http-client-unsafe`, `graphql-unbounded-query`, `context-propagation-missing` | `http.MaxBytesReader` and `io.LimitReader` bound a body read. |
| Cryptography | `crypto-weak-hash`, `crypto-weak-cipher`, `crypto-weak-rand`, `crypto-weak-rsa`, `tls-insecure-config` | `tls-insecure-config` provides fixes for `InsecureSkipVerify` and old `MinVersion` values. |
| Authentication | `jwt-*`, `auth-hardcoded-credential`, `auth-non-constant-time-compare`, `hardcoded-secret` | Covers golang-jwt and similar libraries. Secrets combine provider-specific patterns with an entropy check. |
| Logging | `sensitive-data-in-logs` | Detailed below. |
| Deserialization | `unsafe-gob-decode` | Reports gob decoding of request bodies. |
| Access control | `idor-unscoped-mutation` | Reports updates and deletes keyed only by a request parameter, without an owner or tenant condition. |
| Object properties | `api-excessive-data-exposure`, `api-mass-assignment` | `api-excessive-data-exposure` follows the type of a value written as JSON to an `http.ResponseWriter` (through `json.NewEncoder(w)` or `json.Marshal` and `w.Write`) or passed to gin, echo or fiber `JSON`, through pointers, slices, maps, nested and embedded structs and `gin.H` values. It reports stored secrets such as `PasswordHash`, `Salt`, `PrivateKey`, `TOTPSecret`, `RecoveryCodes`, `SSN` and `CVV` unless the field is tagged `json:"-"` or the type implements `json.Marshaler`. Tokens issued to the client, such as `AccessToken`, are not reported, nor is `Password` in types named `...Request`, `...Input`, `...Login` or `...Credentials`. Note that `json:"-,"` exposes the field under the key `-`. `api-mass-assignment` reports a request body decoded (`json.Decoder` on `r.Body`, `json.Unmarshal` of the body, gin `Bind*`/`ShouldBind*`, echo `Bind`, fiber `BodyParser`) into a database model, recognized by `gorm`, `db`, `bun`, `sql`, `bson` or `xorm` tags or by being passed to `Save`, `Create`, `Update`, `Updates` or `Insert`, when the model has privileged fields such as `IsAdmin`, `Role`, `Permissions`, `Balance`, `Price` or `Verified` that are not tagged `json:"-"` or read-only for gorm. |
| Memory safety | `unsafe-memory-manipulation` | Reports `reflect.SliceHeader` and `reflect.StringHeader`, a `uintptr(unsafe.Pointer(p))` kept in a variable and later converted back to `unsafe.Pointer`, and `unsafe.Slice`/`unsafe.String` whose length is not constant, not derived from `len`/`cap` and not compared before the call. A `uintptr` used only for printing or alignment checks and `unsafe.Add` in a single expression are not reported. |
| Ignored errors | `security-err-ignored` | Reports a dropped error (call statement or `_`) only for calls whose failure leaves the program insecure: `crypto/rand.Read`, `rand.Reader.Read` and `io.ReadFull(rand.Reader, ...)` and bcrypt `CompareHashAndPassword` (Critical); TLS `Handshake`, `x509.Certificate.Verify`, `os.Chmod`/`Chown`/`Lchown` and `syscall.Setuid`/`Setgid`/`Chroot` (High); and `rows.Err()` ignored or never called after a `rows.Next()` loop (Medium). Other ignored errors, such as `fmt.Println` or `Close`, are not reported. |

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

## Reliability rules

Reliability findings use the `reliability` category and are counted
separately in report summaries.

### Transactions and locks across blocking calls

`tx-network-io` and `lock-blocking-io` follow the call graph from the code
between the start and the end of a critical section:

- A transaction starts at `database/sql` `Begin`/`BeginTx`, `sqlx`
  `Beginx`/`BeginTxx`/`MustBegin`, `pgx` `Begin`/`BeginTx` or gorm `Begin`, and
  ends at `Commit` or `Rollback`. The callbacks of gorm `Transaction` and pgx
  `BeginFunc` are critical sections as a whole.
- A lock starts at `Lock`/`RLock` on a `sync.Mutex` or `sync.RWMutex` and ends
  at the matching non-deferred `Unlock`/`RUnlock`. A deferred unlock keeps the
  section open until the function returns.

Blocking calls are outbound HTTP requests (`net/http` functions, `Client`
methods and `RoundTrip`), gRPC `Invoke`/`NewStream`, `net` dials, `net/smtp`
and `time.Sleep`. Calls are followed through up to eight project functions,
including interface calls resolved by the call graph, and the finding shows
the chain. Calls started with `go` are not part of the section.

### Unreleased resources

| Rule | Behavior |
|---|---|
| `sql-tx-missing-rollback` | Reports a transaction without a deferred `Rollback` (directly or in a deferred function) when a return after `Begin` neither calls `Commit`/`Rollback` nor follows such a call in an enclosing block. The return inside the error check of `Begin` is ignored. A transaction that is returned, passed to a function or stored is not reported. |
| `http-body-unclosed` | Reports a response from `http.Get`, `Head`, `Post`, `PostForm` or `Client` methods whose body is never closed, including a response discarded with `_`. Passing `resp.Body` to standard library readers such as `io.ReadAll` does not count as closing it; returning the response or passing it to project code does. |
| `sql-rows-unclosed` | The same check for rows from `Query`/`QueryContext` of `database/sql`, `sqlx` and `pgx`. `QueryRow` is not reported. |
| `defer-in-loop` | Reports `defer` in a `for` or `range` body when both belong to the same function. Running the body in a function literal, which is the usual fix, is not reported. |
| `goroutine-channel-leak` | In a function with a `context.Context` or `*http.Request` parameter, reports a goroutine that sends on an unbuffered channel outside a `select` when the function receives from that channel in a `select` with other cases or can return before receiving. Buffered channels and sends inside a `select` are not reported. |

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
| `rpc` | gRPC server methods: request message parameters, `Recv()` and `RecvMsg()` on server streams, `metadata.FromIncomingContext`; ConnectRPC `*connect.Request[T]`, `*connect.ClientStream[T]` and `*connect.BidiStream[T]` parameters |
| `cli` | `os.Args`, `os.Stdin`, `fmt.Scan*` (confidence 0.7) |
| `env` | `os.Getenv`, `os.LookupEnv` (confidence 0.6) |

A method is a gRPC server method when its receiver embeds a generated
`Unimplemented...Server` or `Unsafe...Server` type, or when it is exported and
has the unary handler shape `func(context.Context, *Req) (*Resp, error)` with
protobuf messages. Generated client methods, which take `...grpc.CallOption`,
are not sources. Taint then follows getters such as `req.GetFilter()` into
services and repositories.

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
| `template-injection` | High | `Template.Parse` of `text/template` and `html/template` |
| `nosql-injection` | High | go-redis v8/v9 `Eval`, `EvalRO` and `ScriptLoad` scripts and `redis.NewScript` |

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

### go.mod hygiene and module provenance

These checks run on every scan, even with `dependencies.enable: false`,
because they only read `go.mod` and `go.sum`. Findings point at the line of
the `require` or `replace` directive, so `--diff` reports a newly added
dependency.

| Rule | Behavior |
| --- | --- |
| `dependency-typosquatting` (`check_provenance`) | Compares each requirement, without its `/vN` suffix and with nested modules reduced to their repository, with a built-in list of about 300 widely used modules. A module that is not in the list but is one edit away (two for paths of 20 characters or more) is reported, counting transpositions and look-alike characters (`rn`/`m`, `l`/`1`, `o`/`0`, dropped `-`) as one edit. Modules under domains that only one organization can publish to (`golang.org/x`, `google.golang.org`, `go.uber.org`, `gopkg.in`, `k8s.io` and others), modules of the same account as the scanned module, and modules under `allowed_prefixes` are not compared. |
| `gomod-local-replace` (`check_hygiene`) | Reports `replace` directives whose target is a directory. |
| `gomod-missing-checksum` (`check_hygiene`) | Reports direct requirements without an `h1:` hash of their content in `go.sum`, or all of them when `go.sum` is missing. Requirements replaced by a directory are skipped; for other replacements the replacement version is checked. |
| `dependency-policy-denied` | Reports modules matching `denied_prefixes`, and, when `allowed_prefixes` is set, every required module outside it, direct or indirect. A prefix matches whole path elements; a prefix ending in `/` or `.` matches any continuation. |

With `dependencies.enable` and `check_vulnerabilities`, the module proxy is
also asked about each requirement. The proxy is the first URL in `GOPROXY`
(default `https://proxy.golang.org`); `direct` or `off` disables the lookups,
and modules matching `GONOPROXY` or `GOPRIVATE` are never sent. Answers are
cached under the user cache directory, `@latest` answers for 24 hours.

| Rule | Behavior |
| --- | --- |
| `dependency-young-module` | Reports a version published fewer than `min_module_age_days` days ago (from `@v/<version>.info`), unless the module is under `allowed_prefixes` or belongs to the scanned module's account. |
| `dependency-deprecated` | Reports a module whose latest `go.mod` has a `// Deprecated:` comment, with the authors' text. |
| `dependency-retracted` | Reports a version inside a `retract` interval of the latest `go.mod`, with the rationale. |

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
`caps verify` then fails when a dependency upgrade adds a capability. When the
lock file exists, `scan` reports the same escalations as
`supply-chain-capability-escalation` findings; the check is offline and is
turned off with `dependencies.check_capabilities: false`. An escalation is Critical
when the module gains exec, cgo or plugin access, or when it gains
environment or network access and now has both. Otherwise it is High.

## SBOM and VEX

`codex-cli sbom [path]` describes the module and its dependencies.

| Flag | Meaning |
| --- | --- |
| `--format` | `cyclonedx` (default, CycloneDX 1.6 JSON) or `spdx` (SPDX 2.3 JSON) |
| `--out` | Output file; `-` (default) writes to stdout, with messages on stderr only |
| `--vex` | Look up vulnerabilities (OSV, Go vulnerability database, GitHub advisories) and add them with a reachability-based status |
| `--vex-out FILE` | Also write the statements as an OpenVEX v0.2.0 document; implies `--vex` |
| `--no-caps` | Leave out dependency capabilities |
| `--offline` | Do not contact vulnerability databases; cannot be combined with `--vex` |
| `--config FILE` | Configuration used to load the module |

Each required module and the standard library becomes a component:

- The package URL has the form `pkg:golang/github.com/gin-gonic/gin@v1.10.0`, and the standard library is `pkg:golang/stdlib@v1.24.2`.
- The `h1:` hash from `go.sum` is decoded into a SHA-256 value and is also kept as the `go:sum` property.
- The license is the SPDX identifier detected in the module cache or `vendor/`.
- Unless `--no-caps` is given, every capability of the module's reachable code is a `codexsentinel:capability` property, with `codexsentinel:capability:evidence:<CAP>` holding a call path.
- Modules replaced by local directories are left out.
- The serial number is derived from the content, so the same input gives the same identifier.

With `--vex`, the CycloneDX `vulnerabilities` section and the OpenVEX
statements use the call graph:

| Reachability | CycloneDX `analysis` | OpenVEX `status` |
| --- | --- | --- |
| No vulnerable symbol is reachable | `not_affected`, `code_not_reachable` | `not_affected`, `vulnerable_code_not_in_execute_path` |
| A vulnerable symbol is reachable | `exploitable`, response `update` | `affected`, with the fixed version and call site |
| The advisory names no symbols | `in_triage` | `under_investigation` |

```bash
codex-cli sbom . --vex --vex-out openvex.json --out sbom.cdx.json
trivy sbom sbom.cdx.json --vex openvex.json
grype sbom:sbom.cdx.json --vex openvex.json
```

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

The default rules in `assets/rules` are compiled into the binary and apply in
every project. Rules from every directory in `rules.rule_paths` and every file
in `rules.rule_files` are added to them; a rule with the same ID replaces the
default one. Files named `example-*.yaml` in `assets/rules` are samples and
are not loaded.

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

### Suppression policy in CI

A failing check can be silenced instead of fixed. With
`--forbid-new-suppressions`, the scan compares the working tree with the
`--diff` reference (`HEAD` by default) and reports each added line that hides
findings as a critical `unauthorized-suppression-added` finding (CWE-693):

- `//codex:ignore`, `//nolint` and `#nosec` directives in Go comments. Files
  are tokenized, so directive-like text inside string literals is ignored.
- New entries in the ignore file (comments do not count).
- Configuration in `.codexsentinel.yaml`, `codex.yaml` and `.golangci.yml`
  that disables rules, excludes paths, turns inline ignores back on, raises
  `min_confidence` or `fail_on_severity`, or turns the policy off. Adding
  default exclusions such as `vendor` or lowering a threshold is not reported.

A directive that a removed line of the same file already contained, such as a
line that was reformatted, is not new. The findings are added after inline
ignores, the ignore file and the baseline are applied, so they cannot be
suppressed, and they fail the scan even without `--strict`. To approve a
reviewed suppression, CI sets `CODEX_ALLOW_SUPPRESSIONS=1`, for instance only
when the pull request carries a label that security reviewers apply.

## Reports

| Format | Contents |
| --- | --- |
| SARIF 2.1.0 | Rules with CWE/OWASP tags and `security-severity`, results with `codeFlows`, `fixes` and `partialFingerprints.primaryLocationLineHash`, git metadata |
| JSON | `summary` (counts per severity and category), `issues`, `generated_at`, `git` |
| HTML | A self-contained page (inline styles, no network requests, light and dark themes) with charts by severity and category, a severity filter, and per finding its location, rule link, CWE, OWASP, confidence, reachability, data-flow trace, fix and patch |
| Markdown | Repository information, summary, tables per severity, details and remediation |
| GitHub | Workflow commands (`::error`, `::warning`, `::notice` with file, line, column and title) that annotate pull requests; written to stdout by default, plus a Markdown job summary with severity counts, the findings and their data-flow traces |
| GitLab | Code Quality JSON array (`description`, `check_name`, `fingerprint`, `severity` blocker/critical/major/minor/info, `location.path`, `location.lines.begin`); `[]` when there are no findings. Default file `gl-code-quality-report.json` |
| Agent | Plain text for automated remediation: a status line, then per finding `ISSUE`, `WHY`, `FLOW`, `FIX` and `PATCH` lines, sorted by severity and location |

Example of the `agent` format:

```text
STATUS: FAIL (1 issues: critical=0 high=1 medium=0 low=0 info=0)
---
ISSUE [HIGH] sql-injection (CWE-89) at internal/repo/user.go:42:15-42:68
WHY: Untrusted input reaches SQL query execution via string concatenation.
FLOW: handler/user.go:18 (source: (*http.Request).FormValue) -> internal/repo/user.go:42 (sink: (*sql.DB).QueryContext)
FIX: Use parameterized placeholders ($1 / ?) instead of string concatenation.
```

`FLOW` appears for findings with a trace and `PATCH` for findings with a fix;
a scan without findings prints only `STATUS: PASS (0 issues)`.

## Language server and MCP server

Both servers speak JSON-RPC 2.0 on stdin/stdout and write nothing else to
stdout; logs go to stderr (warnings) or to `--log-file`.

**`codex-cli lsp`**

- `initialize` takes the workspace from `rootUri`, `workspaceFolders` or
  `rootPath`; the configuration is read from the module root.
- Documents are analyzed when they are opened or saved
  (`textDocumentSync.change` is none). A save cancels an analysis that is still
  running, and `--debounce` (default 200ms) merges rapid saves.
- `textDocument/publishDiagnostics` is sent for every file with findings, and
  with an empty array for files whose findings are gone. Ranges are 0-based and
  counted in UTF-16 code units. Diagnostic `code` is the rule ID, severity maps
  critical and high to Error, medium to Warning and low to Information, and the
  message contains CWE, OWASP, the fix and the data flow; trace steps are also
  listed as related information.
- `textDocument/codeAction` returns, for findings in the requested range, the
  rule's fix as a preferred quick fix and an action that appends
  `//codex:ignore <rule> -- TODO: document reason` to the line, unless
  `suppression.forbid_new_suppressions` is set.
- `shutdown` followed by `exit` ends the server with status 0.

**`codex-cli mcp`**

Messages are one JSON object per line; Content-Length framed input is
accepted as well. The server negotiates protocol versions 2025-06-18,
2025-03-26 and 2024-11-05 and answers `initialize`, `ping`, `tools/list` and
`tools/call`. Tool arguments are validated against their schema: unknown
arguments, missing required ones and invalid severities are rejected with
error -32602. Scan results use the [agent report format](#reports); a failed
analysis is returned as a result with `isError: true`.

| Tool | Arguments |
| --- | --- |
| `scan_path` | `path` (required), `severity`, `deps_only` |
| `scan_diff` | `path`, `git_ref` (required), `forbid_new_suppressions` |
| `verify_capabilities` | `path` (required), `lockfile` |
| `explain_rule` | `rule` (required): ID or code |
| `list_rules` | `category` |

## Configuration reference

The configuration file is named `.codexsentinel.yaml`, `.codexsentinel.yml`,
`codex.yaml` or `.codex.yml`, checked in that order in each directory. It is
looked for in the root of the scanned module (or go.work workspace), then in
its parent directories up to the repository root (the directory containing
`.git`), and finally in the current directory. It can also be given with
`--config`. Relative `rules.rule_paths` and `rules.rule_files` are resolved
against the directory of the configuration file. The language server applies
the same lookup to each workspace it analyzes, so
`suppression.forbid_new_suppressions` follows the project being edited.
Unknown keys and invalid values are errors. Omitted keys keep their defaults.

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
| `scan.enable_cache` | `true` | Reuse cached results of unchanged packages |
| `scan.cache_dir` | `""` | Cache directory; empty uses `$CODEXSENTINEL_CACHE_DIR` or the user cache directory |
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
| `dependencies.check_capabilities` | `true` | Verify the capability lock file during `scan` |
| `dependencies.capability_lockfile` | `.codexsentinel.caps.json` | Lock file path, relative to the module root |
| `dependencies.allow_licenses`, `deny_licenses` | see README | SPDX identifiers |
| `dependencies.check_provenance`, `check_hygiene` | `true` | go.mod checks; proxy lookups only with `enable` |
| `dependencies.min_module_age_days` | `7` | Minimum age of a required version; 0 disables |
| `dependencies.allowed_prefixes`, `denied_prefixes` | empty | Module path policy |
| `suppression.ignore_file` | `.codexsentinel.ignore` | Ignore file, relative to the module root |
| `suppression.enable_inline_ignore` | `true` | Honor `//codex:ignore` |
| `suppression.require_ignore_reason` | `false` | Report directives without a reason |
| `suppression.min_confidence` | `0.5` | Drop findings below this confidence |
| `suppression.forbid_new_suppressions` | `false` | Fail scans whose changes add suppressions, as `--forbid-new-suppressions` does |
| `report.formats` | `[sarif]` | Formats written when `--format` is not given, each to its file in `report.output_dir` |
| `report.output_dir` | `scan_reports` | Default report directory |
| `report.fail_on_severity` | `""` | Exit with code 1 when findings at or above this severity remain |
