# CodexSentinel Wiki

CodexSentinel is an interprocedural static analyzer for code written for Go
1.24 and newer; building it requires Go 1.26 or newer. It covers security,
production reliability, architecture, code quality and the supply chain of a
module, and writes its findings as SARIF, JSON, HTML, Markdown, GitHub
annotations, GitLab Code Quality or a compact plain-text report.

## Pages

| Page | Contents |
| --- | --- |
| [Quick Start](WIKI_QUICK_START.md) | Install, `init`, first scan, pull request gate, baseline, fixes, capabilities, SBOM and CI |
| [Documentation](WIKI_DOCUMENTATION.md) | The scan pipeline, how each analysis works, cache, suppressions, report formats, language and MCP servers, configuration reference |
| [Examples](WIKI_EXAMPLES.md) | Vulnerable and fixed code for the main rules; CI pipelines for GitHub, GitLab and pre-commit; custom YAML rules and taint specifications; OpenVEX with Trivy and Grype |
| [API Reference](WIKI_API_REFERENCE.md) | Every command and flag, exit codes, report formats, and the Go API: engine, catalog, reports, `go/analysis` analyzers and the golangci-lint plugin |
| [Rule reference](docs/rules/README.md) | One page per rule (CS001 to CS085), generated from the rule catalog |
| [Benchmarks](docs/BENCHMARKS.md) | Precision, recall and speed on reproducible corpora, compared with gosec and govulncheck |

## Commands at a glance

| Command | Purpose |
| --- | --- |
| `codex-cli init` | Write a configuration tailored to the module |
| `codex-cli scan` | Analyze a module; `--diff`, `--baseline`, `--fix`, `--forbid-new-suppressions` |
| `codex-cli rules`, `codex-cli explain` | List and explain the rules |
| `codex-cli caps inspect\|lock\|verify` | Dependency capability lock file |
| `codex-cli sbom` | CycloneDX or SPDX SBOM, OpenVEX with `--vex-out` |
| `codex-cli baseline create` | Accept the current findings |
| `codex-cli mark` | Add an ignore-file entry |
| `codex-cli cache status\|clean` | Analysis cache |
| `codex-cli lsp`, `codex-cli mcp` | Language Server Protocol and Model Context Protocol servers |
| `codex-cli version` | Version and build information |

## What a scan does

1. **Load.** The module is loaded once with `go/packages`, with syntax and type information.
   - Excluded paths, generated files and (by default) tests are left out of the analysis.
   - They stay available for type checking.
2. **Package rules.** The built-in and YAML rules run on every package, and their results are cached per package. Built-in rules resolve calls through type information.
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
- **Reliability**: network calls inside transactions or under a mutex, missing rollbacks, unclosed bodies and rows, `defer` in loops, leaking goroutines.
- **API exposure**: secrets and internal fields serialized to JSON responses, request bodies decoded into stored models.
- **Supply chain**: typosquatted, young, retracted and deprecated modules, local `replace` directives, missing `go.sum` hashes, module allow and deny lists, CycloneDX 1.6 and SPDX 2.3 SBOMs with reachability-based OpenVEX.
- **Workflow**: `init` for a tailored configuration, `--diff` for pull requests, `--baseline` for existing code, `--fix` for mechanical fixes, `//codex:ignore` with reasons, and `--forbid-new-suppressions` to stop changes that silence findings instead of fixing them.
- **Integration**: a GitHub Action with pull request annotations, GitLab Code Quality reports, pre-commit hooks, a language server for editors, an MCP server, and `pkg/codexlint` with the built-in rules as `go/analysis` analyzers for gopls, multichecker and golangci-lint v2 module plugins.

## Limits

- The analysis is static. Findings depend on what type information and the
  call graph can resolve. Reflection, `unsafe` and code generated at run time
  are not followed.
- Package-level rules are intraprocedural unless noted; data crossing
  functions is covered by the taint engine.
- The dependency audit (vulnerabilities, licenses and module proxy lookups)
  needs network access and is disabled by default (`dependencies.enable`); the `go.mod` hygiene,
  typosquatting and capability checks run offline.
- The `go/analysis` analyzers contain only the package-level rules; taint,
  dependency, architecture and metrics analyses run in `codex-cli scan`.

## Project links

- Source and issues: <https://github.com/Voskan/codexsentinel>
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy: [SECURITY.md](SECURITY.md)
- License: [MIT](LICENSE)
