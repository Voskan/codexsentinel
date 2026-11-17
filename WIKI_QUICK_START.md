# Quick Start

## 1. Install

With Go 1.26 or newer:

```bash
go install github.com/Voskan/codexsentinel/v2/cmd/codex-cli@latest
```

Or with the install script. It verifies release binaries against the
published checksums and falls back to `go install`:

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
```

Or build the container image, which includes the Go toolchain the analysis
needs:

```bash
docker build -t codexsentinel .
```

Check the installation:

```bash
codex-cli version
```

## 2. Generate a configuration

```bash
codex-cli init --with-caps
```

`init` reads `go.mod` and the directory tree and writes a commented
`.codexsentinel.yaml`: architecture layers for directories with common layer
names (`handler`, `service`, `domain`, `repository` and similar), the allowed
dependencies between them, and exclusions for mocks and generated code. It
also creates an empty `.codexsentinel.ignore` and, with `--with-caps`, the
capability lock file `.codexsentinel.caps.json`. Commit all three.

## 3. Scan a module

Run the scan from the module root, or pass its path:

```bash
codex-cli scan .
```

The findings are printed as a summary, and a SARIF report is written to
`scan_reports/codex-report.sarif`. Choose another format or location with
`--format` and `--out`:

```bash
codex-cli scan . --format html --out report.html
```

```bash
codex-cli scan . --format json --out report.json
```

## 4. Read a finding

A taint finding in the JSON report looks like this:

```json
{
  "rule_id": "sql-injection",
  "severity": "HIGH",
  "file": "main.go",
  "line": 12,
  "description": "Untrusted data flows into a SQL query (untrusted input returned by (net/http.Request).FormValue)",
  "cwe": "CWE-89",
  "owasp": "A05:2025",
  "confidence": 1,
  "trace": [
    {"location": {"file": "main.go", "line": 12, "column": 72}, "message": "untrusted input returned by (net/http.Request).FormValue", "kind": "source"},
    {"location": {"file": "main.go", "line": 12, "column": 21}, "message": "reaches (database/sql.DB).Query", "kind": "sink"}
  ],
  "fingerprint": "1f025e3a…",
  "suggestion": "Use parameterized queries with placeholders ($1 or ?) instead of building SQL from untrusted input."
}
```

- `trace` lists the steps from the untrusted source to the sink. In SARIF it
  becomes a code flow that GitHub code scanning displays step by step.
- `fingerprint` identifies the finding across line shifts. Baselines use it.

Look up any rule with `explain`, by ID or by code:

```bash
codex-cli explain sql-injection
```

```bash
codex-cli rules --category reliability
```

## 5. Narrow the results

```bash
codex-cli scan . --severity high       # high and critical only
codex-cli scan . --diff origin/main    # only lines changed since origin/main
```

To adopt the tool on an existing code base, record today's findings and fail
only on new ones:

```bash
codex-cli baseline create . --out .codexsentinel.baseline.json
```

```bash
codex-cli scan . --baseline .codexsentinel.baseline.json --strict
```

The pull request gate combines the diff with a check that the change does not
silence findings instead of fixing them:

```bash
codex-cli scan . --diff origin/main --forbid-new-suppressions --strict
```

## 6. Apply fixes

```bash
codex-cli scan . --fix
```

`--fix` applies the mechanical fixes that rules provide, for example
re-enabling TLS certificate verification. Review the diff before committing.

## 7. Configure

`.codexsentinel.yaml` in the module root holds the configuration. Only the
keys you change are needed; everything else keeps its default:

```yaml
version: 1
rules:
  disabled: [context-propagation-missing]
  severity_overrides:
    ssrf: high
metrics:
  max_cyclomatic: 20
dependencies:
  enable: true            # queries OSV and the Go vulnerability database
suppression:
  require_ignore_reason: true
```

See the [configuration reference](WIKI_DOCUMENTATION.md#configuration-reference).

## 8. Suppress a false positive

```go
resp, err := client.Do(req) //codex:ignore ssrf -- the URL is the configured API endpoint
```

## 9. Guard dependencies

The capability lock file records which privileged capabilities (file system,
network, environment, processes, `reflect`, `unsafe`, cgo, plugins) each
dependency uses from reachable code. After a dependency upgrade, `verify`
fails when a dependency starts using a capability the lock file does not
approve:

```bash
codex-cli caps verify .
```

```bash
codex-cli caps lock .
```

`lock` records the new state once the change has been reviewed. For release
artifacts, write an SBOM with VEX data; unreachable vulnerabilities are marked
`not_affected`:

```bash
codex-cli sbom . --vex --out sbom.cdx.json --vex-out openvex.json
```

## 10. Add it to CI

```yaml
name: CodexSentinel
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Voskan/codexsentinel@v2
        with:
          severity: medium
          diff: ${{ github.event_name == 'pull_request' && format('origin/{0}', github.base_ref) || '' }}
          forbid-new-suppressions: ${{ github.event_name == 'pull_request' }}
```

The action annotates the findings' lines in the pull request, writes a job
summary, fails the step when findings at or above `severity` remain, and runs
`caps verify` when the lock file exists. It needs no GitHub Advanced Security.
GitLab, pre-commit and SARIF upload are shown in the
[examples](WIKI_EXAMPLES.md#continuous-integration).

## Next steps

- [Documentation](WIKI_DOCUMENTATION.md): how each analysis works.
- [Examples](WIKI_EXAMPLES.md): code that triggers each main rule, and its fix.
