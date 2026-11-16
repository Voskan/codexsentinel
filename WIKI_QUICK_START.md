# Quick Start

## 1. Install

With Go 1.24 or newer:

```bash
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
```

Or with the install script. It verifies release binaries against the
published checksums and falls back to `go install`:

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
```

Check the installation:

```bash
codex-cli version
```

## 2. Scan a module

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

## 3. Read a finding

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

## 4. Narrow the results

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

## 5. Configure

Create `.codexsentinel.yaml` in the module root. Only the keys you change are
needed; everything else keeps its default:

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

## 6. Suppress a false positive

```go
resp, err := client.Do(req) //codex:ignore ssrf -- the URL is the configured API endpoint
```

## 7. Add it to CI

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

`--strict` makes the job fail (exit code 1) when findings at or above the
`--severity` level remain. The SARIF upload shows them in the repository's
code scanning alerts.

To guard dependency upgrades as well, commit a capability lock file and verify
it in CI:

```bash
codex-cli caps lock .
```

```bash
codex-cli caps verify .
```

## Next steps

- [Documentation](WIKI_DOCUMENTATION.md): how each analysis works.
- [Examples](WIKI_EXAMPLES.md): code that triggers each main rule, and its fix.
