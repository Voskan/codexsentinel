# Contributing to CodexSentinel

Thanks for helping improve CodexSentinel. This guide covers the development
environment, how the analyzer is organized, and how to add and test a rule.

## Development environment

- Go 1.26 or newer (the version in `go.mod` is the minimum).
- git (the diff mode and several tests run `git`).
- Optional: [golangci-lint](https://golangci-lint.run) v2 for `make lint`, Docker for `make docker-build`.

```bash
git clone https://github.com/Voskan/codexsentinel.git
cd codexsentinel
make build        # builds build/codex-cli
make test         # go test -race ./...
make lint         # golangci-lint run
make scan         # scan this repository as CI does
make docs         # regenerate docs/rules from the rule catalog
```

Before opening a pull request, run:

```bash
gofmt -l $(go list -f '{{.Dir}}' ./...)   # must print nothing
go vet ./...
go test -race ./...
go run ./cmd/docgen -out docs/rules && git diff --exit-code docs/rules
go run ./cmd/codex-cli scan . --strict --severity low --format agent --out -
```

The project scans itself in CI with `--strict --severity low` and must stay
at `STATUS: PASS (0 issues)`; a change must not introduce new findings, and
the rule reference in `docs/rules` must match the catalog.

## Architecture

A scan loads the target module once and shares the result between all analyses.

| Package | Responsibility |
| --- | --- |
| `analyzer/workspace` | Loads packages with `go/packages` (syntax and type information), applies scan exclusions and selects the files to analyze. |
| `analyzer/ssa` | Builds the SSA program and the VTA call graph for the workspace; entrypoints and reachability queries. |
| `analyzer/flow` | Interprocedural taint engine: sources, sanitizers and sinks with function summaries and traces. |
| `analyzer/rules/builtin` | Built-in AST and type-based rules (`sql-injection`, `path-traversal`, `jwt-missing-alg-check`, ...). |
| `analyzer/catalog` | The rule catalog: code, ID, severity, category, CWE, OWASP, explanation and examples of every rule. |
| `analyzer/cache` | The per-package result cache. |
| `analyzer/rules/yaml` | Structural pattern rules loaded from YAML (`assets/rules`), including autofixes. |
| `analyzer/engine` | Orchestrates the analyses, applies configuration, suppressions, deduplication, fingerprints and ordering. |
| `analyzer/baseline` | Stable finding fingerprints and the baseline file. |
| `analyzer/fixer` | Applies suggested fixes to source files. |
| `arch` | Architecture checks: layer dependencies, import cycles, god structs, boundary type leaks. |
| `deps` | Dependency audit: OSV/GitHub advisories with call-graph reachability, licenses, module provenance, capability lock file, SBOM and VEX. |
| `metrics` | Complexity, size, duplication, mutable global state and dead code. |
| `report`, `report/formats` | SARIF, JSON, HTML, Markdown, agent, GitHub and GitLab reports. |
| `internal/git` | Diff mode and the detection of newly added suppressions. |
| `internal/jsonrpc`, `internal/lsp`, `internal/mcp` | The language server and the Model Context Protocol server. |
| `internal/docgen`, `cmd/docgen` | Generates `docs/rules` from the catalog. |
| `pkg/codexlint` | The built-in rules as `go/analysis` analyzers for multichecker, gopls and golangci-lint. |
| `cmd/codex`, `cmd/codex-cli` | The command line interface. |
| `benchmarks` | Precision, recall and speed benchmarks on the corpora in `benchmarks/corpus`. |

Findings are `result.Issue` values. File paths are relative to the module root
and positions are 1-based.

## Writing a rule

Built-in rules live in `analyzer/rules/builtin`. A rule declares its metadata
once and reports through the shared reporter:

```go
var exampleMeta = ruleMeta{
	ID: "example-rule", Title: "Example Rule", Severity: result.SeverityHigh,
	CWE: "CWE-000", OWASP: "A00:2025", Confidence: 0.8,
	Suggestion: "Explain how to fix the problem.",
}

// RegisterExampleRule reports ...
func RegisterExampleRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{exampleMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if ok && isFunc(calleeFunc(info, call), "os", "Exit") {
					r.report(exampleMeta, call, "Explain what is wrong here.")
				}
				return true
			})
		}
	})
}
```

Guidelines:

- Resolve calls through type information (`calleeFunc`, `isFunc`, `isMethod`,
  `typeIs`) instead of matching identifier names, so aliases and renamed
  imports are handled and look-alike local functions are not.
- Prefer reporting only when untrusted data reaches the sink (`newLocalTaint`,
  or the interprocedural engine in `analyzer/flow` for data crossing functions).
- Set `Confidence` honestly; findings below `suppression.min_confidence` are dropped.
- Attach a `result.SuggestedFix` when the fix is mechanical.
- Add the registration function to `RegisterAll` in `analyzer/rules/builtin/registry.go`.
- Document the rule in `analyzer/catalog` with the next free code (the
  highest is `CS085`), an explanation and a problematic and a safe example
  that parse as Go, then run `make docs-generate` to update `docs/rules`.
  Tests fail when a registered rule is missing from the catalog or the
  reference is out of date.
- Run the benchmarks (`go test ./benchmarks/`) when a rule could report code
  in the safe corpus; the test fails on any false positive there.

## Testing a rule

Rule tests use the harness in `analyzer/testutil`. Fixtures are in-memory
modules; each line expected to produce a finding carries a `// want` comment
with the rule ID and, optionally, a message substring:

```go
func TestExampleRule(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import "os"

func stop() {
	os.Exit(1) // want "example-rule"
}

func fine() {}
`}, RegisterExampleRule)
}
```

`RunRulesOnFiles` fails on missing and on unexpected findings, so cover both
the vulnerable and the safe variants of the code. Fixtures that need
third-party packages can add small stub modules to the file map with a
`replace` directive in `go.mod`. Tests must not touch the network or the
repository tree; use `t.TempDir()` for files.

Analyzers in `pkg/codexlint` are tested with `analysistest` against
`pkg/codexlint/testdata/src`.

## Suppressions in this repository

Prefer fixing a finding. When a finding is a false positive, suppress it at
the line with a justification:

```go
data, err := os.ReadFile(path) //codex:ignore path-traversal -- path comes from the module cache
```

## Commit and pull request conventions

- Keep commits focused and use conventional prefixes (`feat(scope):`, `fix(scope):`, `docs:`, `chore:`).
- Describe the behavior change and how it was tested in the pull request.
- New rules need tests for true positives and for the safe patterns they must ignore.

## Reporting security issues

Do not open public issues for vulnerabilities in CodexSentinel itself; follow
[SECURITY.md](SECURITY.md).
