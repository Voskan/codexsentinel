# API Reference

CodexSentinel can be embedded as a Go library or run through the standard
`go/analysis` framework. This page covers the stable entry points. For every
exported identifier, see the
[package documentation](https://pkg.go.dev/github.com/Voskan/codexsentinel).

Module path: `github.com/Voskan/codexsentinel`

## Contents

- [Running a scan](#running-a-scan)
- [Configuration](#configuration)
- [Findings](#findings)
- [Reports](#reports)
- [Baselines](#baselines)
- [Applying fixes](#applying-fixes)
- [Dependencies and capabilities](#dependencies-and-capabilities)
- [go/analysis analyzers](#goanalysis-analyzers)
- [golangci-lint v2 plugin](#golangci-lint-v2-plugin)
- [Writing built-in rules](#writing-built-in-rules)

## Running a scan

```go
import (
	"context"
	"fmt"
	"log"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/config"
)

func main() {
	cfg := config.NewDefaultConfig()
	cfg.Rules.Disabled = []string{"context-propagation-missing"}

	issues, err := engine.Run(context.Background(), "./...", &cfg)
	if err != nil {
		log.Fatal(err)
	}
	for _, issue := range issues {
		fmt.Printf("%s:%d %s %s\n", issue.Location.File, issue.Location.Line, issue.ID, issue.Severity)
	}
}
```

`engine.Run(ctx, path, cfg)`:
- **Input.** `path` is a module directory, a pattern ending in `/...` or a single `.go` file. A `nil` config uses the defaults. An invalid config is returned as an error.
- **Work.** The workspace is loaded once, then all enabled analyses run: package rules, taint, dependencies, architecture, metrics and the capability check.
- **Output.** Suppressions, deduplication, fingerprints and ordering are already applied to the returned findings. Their file paths are relative to the module root.
- **Cancellation.** Cancelling `ctx` stops the scan and returns the context error.

YAML rules are not loaded by `engine.Run` itself. Compile them and pass them
to `engine.RunWithOptions`, which keeps repeated runs in one process
independent:

```go
compiled, err := yaml.LoadFromFS(assets.BuiltinRulesFS, "rules") // the default rules
more, err := yaml.CompileDir("rules")                              // your own rules
opts := engine.Options{Rules: yaml.Registrations(append(compiled, more...))}
issues, err := engine.RunWithOptions(ctx, "./...", &cfg, opts)
```

`yaml.LoadFromDir(dir)` still registers rules in the global registry used by
`engine.Run`; loading the same files again replaces them.

`Options.Cache` takes an `analyzer/cache.Cache` (`cache.Open(dir)`) to store
package results in a directory of your choice and to read its `Stats()` after
the run. Without it, the engine uses `scan.cache_dir` while
`scan.enable_cache` is true.

## Configuration

Package `config`:

| Function | Purpose |
| --- | --- |
| `NewDefaultConfig() Config` | Defaults, deep-copied so they can be modified |
| `LoadFromPath(path) (*Config, error)` | Read a YAML file over the defaults; unknown keys are errors |
| `FindDefaultConfigFile(dir) string` | `.codexsentinel.yaml`, `.codexsentinel.yml`, `codex.yaml` or `.codex.yml` in `dir`, or `""` |
| `Validate(*Config) error` | Check the version, thresholds, severities, confidence range and report formats |

The fields mirror the YAML keys. For example, `Rules.Disabled` is
`rules.disabled` and `Taint.CustomSinks` is `taint.custom_sinks`. See the
[configuration reference](WIKI_DOCUMENTATION.md#configuration-reference).

## Findings

Package `analyzer/result`:

```go
type Issue struct {
	ID          string        // rule ID, e.g. "sql-injection"
	Title       string
	Description string
	Severity    Severity      // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence  float64       // 0..1
	CWE, OWASP  string
	Location    Location      // File (relative), Line, Column, EndLine, EndColumn, Function, PackagePath
	Category    string        // security, metrics, architecture, license, style, ...
	Suggestion  string
	References  []string
	Trace       []TraceStep   // source-to-sink steps for taint findings
	Fix         *SuggestedFix // byte-offset text edits, applied by --fix
	Fingerprint string        // stable identifier used by baselines and SARIF
	Reachable   *bool         // dependency findings: reachable from the program
	// ...
}
```

`result.ParseSeverity` converts strings case-insensitively, and
`result.AllSeverities` lists the levels from highest to lowest. An `Issue`
marshals to JSON directly.

## Reports

The report writers in `report/formats` take `report.Issue`, the flat
representation used by all formats:

| Function | Output |
| --- | --- |
| `formats.BuildSARIF(issues, git) ([]byte, error)` | SARIF 2.1.0 log |
| `formats.WriteSARIFReport(issues, path, git)` | SARIF file |
| `formats.WriteJSONReport(issues, path, git)` | JSON with summary |
| `formats.WriteHTMLReport(issues, path, git)` | HTML page |
| `formats.WriteMarkdownReport(issues, path, git)` | Markdown |

`git` is an optional `*report.GitMetadata` (repository, branch, commit,
author). Convert engine findings field by field:

```go
func toReport(in []result.Issue) []report.Issue {
	out := make([]report.Issue, len(in))
	for i, is := range in {
		out[i] = report.Issue{
			RuleID: is.ID, Title: is.Title, Description: is.Description,
			Severity: report.SeverityLevel(is.Severity), Confidence: is.Confidence,
			CWE: is.CWE, OWASP: is.OWASP, Category: is.Category, Suggestion: is.Suggestion,
			File: is.Location.File, Line: is.Location.Line, Column: is.Location.Column,
			EndLine: is.Location.EndLine, EndColumn: is.Location.EndColumn, Package: is.Location.PackagePath,
			References: is.References, Trace: is.Trace, Fix: is.Fix,
			Fingerprint: is.Fingerprint, Reachable: is.Reachable,
		}
	}
	return out
}
```

`report.ComputeSummary(issues)` returns the counts per severity and category
that the JSON and HTML reports show.

## Baselines

Package `analyzer/baseline`:

```go
b := baseline.New(issues, time.Now())     // record findings (they need fingerprints)
err := b.Write(".codexsentinel.baseline.json")

known, err := baseline.Load(".codexsentinel.baseline.json")
fresh, removed := known.Filter(issues)     // findings not in the baseline
```

`engine.Run` already assigns fingerprints. `baseline.Fingerprint(rule, file,
scope, line, occurrence)` exposes the hash for other tools.

## Applying fixes

Package `analyzer/fixer`:

```go
changed, err := fixer.ApplyFixes(root, issues) // root: the module root of the scan
```

Edit paths in engine findings are relative to the module root, like their
locations, and `ApplyFixes` resolves them against `root`. Fixes that overlap
an earlier fix are skipped, and a file whose fixed source no longer parses is
left unchanged and reported in `err`.

## Dependencies and capabilities

Package `deps`:

```go
reports, err := deps.ScanDependencies(ctx, "go.mod", deps.ScanOptions{
	CheckVulnerabilities: true,
	CheckLicenses:        true,
	AllowLicenses:        []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
})
issues := deps.ReportIssues(reports, "go.mod")
```

- `ScanOptions.Bundle` takes an SSA bundle (`analyzer/ssa.BuildFromWorkspace`). With a bundle, each vulnerability's `Reachable` field is set.
- `OSV` and `GHSA` accept clients with a custom HTTP client or base URL, for example in tests.

Capabilities:

```go
ws, err := workspace.Load(ctx, ".", &cfg)
bundle, err := codessa.BuildFromWorkspace(ws)
current, err := deps.AnalyzeCapabilities(ws, bundle)

lock, err := deps.LoadCapabilityLock(".codexsentinel.caps.json")
escalations := deps.DiffCapabilities(lock, current)
issues := deps.EscalationIssues(escalations, ".codexsentinel.caps.json")

err = deps.WriteCapabilityLock(".codexsentinel.caps.json", current.Lock())
```

## go/analysis analyzers

Package `pkg/codexlint` exposes the built-in package-level rules as
`*analysis.Analyzer` values, one per rule. Each is named `codex_<rule_id>`
(`codex_sql_injection`), and each diagnostic carries the rule ID as its
`Category`, plus suggested fixes when the rule provides them.
`//codex:ignore` directives are honored.

```go
package main

import (
	"github.com/Voskan/codexsentinel/pkg/codexlint"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() { multichecker.Main(codexlint.Analyzers(nil)...) }
```

| Function | Purpose |
| --- | --- |
| `Analyzers(cfg *config.Config)` | Analyzers for the rules enabled in `cfg` (`nil` uses the defaults) |
| `New(settings any)` | Analyzers from a `Settings` value or any JSON-compatible map |
| `AnalyzerName(ruleID)` | The analyzer name for a rule ID |

```go
type Settings struct {
	Enabled            []string `json:"enabled"`              // rule IDs or globs
	Disabled           []string `json:"disabled"`
	MinConfidence      *float64 `json:"min_confidence"`
	EnableInlineIgnore *bool    `json:"enable_inline_ignore"`
}
```

The analyzers do not include the interprocedural taint engine or the
dependency, architecture and metrics analyses, which need the whole program.

## golangci-lint v2 plugin

`codexlint.NewPlugin(settings)` returns a value implementing the module plugin
contract (`BuildAnalyzers`, `GetLoadMode` = `typesinfo`). It does not depend
on golangci-lint. Register it in a small plugin module:

```go
package codexsentinelplugin

import (
	"github.com/Voskan/codexsentinel/pkg/codexlint"
	"github.com/golangci/plugin-module-register/register"
)

func init() {
	register.Plugin("codexsentinel", func(settings any) (register.LinterPlugin, error) {
		return codexlint.NewPlugin(settings)
	})
}
```

`.custom-gcl.yml`:

```yaml
version: v2.1.0
plugins:
  - module: example.com/codexsentinelplugin
    path: ./codexsentinelplugin
```

`.golangci.yml`:

```yaml
version: "2"
linters:
  enable:
    - codexsentinel
  settings:
    custom:
      codexsentinel:
        type: module
        settings:
          disabled: [context-propagation-missing]
          min_confidence: 0.7
```

Build the custom binary with `golangci-lint custom` and run it as
`./custom-gcl run`.

## Writing built-in rules

Rules in `analyzer/rules/builtin` declare their metadata once and report
through a shared reporter that fills in CWE, OWASP, confidence and the
location:

```go
var exampleMeta = ruleMeta{
	ID: "example-rule", Title: "Example Rule", Severity: result.SeverityHigh,
	CWE: "CWE-000", OWASP: "A00:2025", Confidence: 0.8,
	Suggestion: "Explain how to fix the problem.",
}

func RegisterExampleRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{exampleMeta}, func(r *reporter) {
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if ok && isFunc(calleeFunc(r.pass.TypesInfo, call), "os", "Exit") {
					r.report(exampleMeta, call, "Explain what is wrong here.")
				}
				return true
			})
		}
	})
}
```

Add the function to `RegisterAll` in `analyzer/rules/builtin/registry.go`.
Test it with `testutil.RunRulesOnFiles` and `// want "rule-id"` comments; see
[CONTRIBUTING.md](CONTRIBUTING.md).
