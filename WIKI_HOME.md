# CodexSentinel Wiki

CodexSentinel is a static analyzer for Go modules. It covers security,
dependencies, architecture and code quality, and writes its findings as
SARIF, JSON, HTML and Markdown.

## Pages

| Page | Contents |
| --- | --- |
| [Quick Start](WIKI_QUICK_START.md) | Install, first scan, reading the report, CI setup |
| [Documentation](WIKI_DOCUMENTATION.md) | How each analysis works, configuration reference, suppressions, report formats |
| [Examples](WIKI_EXAMPLES.md) | Vulnerable and fixed code for the main rules, with the findings they produce |
| [API Reference](WIKI_API_REFERENCE.md) | Using CodexSentinel as a Go library and through `go/analysis` |

## What a scan does

1. **Load.** The module is loaded once with `go/packages`, with syntax and type information.
   - Excluded paths, generated files and (by default) tests are left out of the analysis.
   - They stay available for type checking.
2. **Package rules.** 37 built-in rules run on every package. Each resolves calls through type information.
3. **Whole-program analyses.** These share one SSA program and VTA call graph:
   - interprocedural taint tracking
   - dependency vulnerability reachability
   - the capability lock check
   - architecture checks
   - metrics and dead code
4. **Post-processing**, in this order:
   1. Rule selection and severity overrides
   2. The confidence threshold
   3. Inline and file-based suppressions
   4. Deduplication of findings for the same rule and line
   5. Stable fingerprints
   6. Deterministic ordering

## Feature overview

- **Taint analysis** of SQL, command, path traversal, SSRF, XSS and open redirect flows across function calls, with traces exported as SARIF `codeFlows`.
- **Security rules** for cryptography, TLS, JWT, cookies, CSRF (including Go 1.25 `http.CrossOriginProtection`), CORS, WebSocket origins, GraphQL limits, archive extraction, unbounded reads and allocations, gob decoding and hardcoded secrets.
- **Path traversal** checks that recognize Go 1.24 `os.Root` as confined access.
- **Log hygiene**: credentials and personal data in `slog`, `zap`, `zerolog` and `log` calls, honoring `slog.LogValuer` and the zap and zerolog marshaler interfaces.
- **Dependencies**: OSV and Go vulnerability database lookups for modules and the standard library, GitHub advisories with `GITHUB_TOKEN`, call-graph reachability, license policy.
- **Capability lock file**: `codex-cli caps lock` / `caps verify` detect dependencies that start using the file system, network, environment, processes, `reflect`, `unsafe`, cgo or plugins.
- **Architecture**: layer rules, import cycles, god structs, boundary type leaks.
- **Metrics**: cyclomatic complexity, function and file length, duplicated function bodies, mutable globals, dead code.
- **Workflow**: `--diff` for pull requests, `--baseline` for existing code, `--fix` for mechanical fixes, `//codex:ignore` with reasons.
- **Integration**: `pkg/codexlint` exposes the built-in rules as `go/analysis` analyzers for gopls, multichecker and golangci-lint v2 module plugins.

## Limits

- The analysis is static. Findings depend on what type information and the
  call graph can resolve. Reflection, `unsafe` and code generated at run time
  are not followed.
- Package-level rules are intraprocedural unless noted; data crossing
  functions is covered by the taint engine.
- Dependency checks need network access and are disabled by default
  (`dependencies.enable`).
- The `go/analysis` analyzers contain only the package-level rules; taint,
  dependency, architecture and metrics analyses run in `codex-cli scan`.

## Project links

- Source and issues: <https://github.com/Voskan/codexsentinel>
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy: [SECURITY.md](SECURITY.md)
- License: [MIT](LICENSE)
