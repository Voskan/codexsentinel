# CodexSentinel

**CodexSentinel** is a powerful, blazing-fast static code analyzer for **Go**, built to identify security vulnerabilities, bad practices, architectural violations, and dependency risks. Designed for developers, DevSecOps, and auditors, it supports both CLI usage and structured JSON reports for integration with CI/CD pipelines.

---

## 🚀 Features

- 🔍 **OWASP Top 10** & common vulnerability detection (XSS, SQLi, SSRF, etc.)
- 📦 **Third-party dependency audit** (licenses, entropy, vulnerabilities via OSV)
- 🧠 **Taint analysis** and SSA-based dataflow tracing
- 📐 **Architecture compliance** (direct calls, layer violations)
- 📏 **Code metrics** (cyclomatic complexity, size, duplication, dead code)
- 🔕 `.codexsentinel.ignore` support for suppressions
- ⚡ **CLI-first experience**, ready for automation and pipelines
- 📄 **Reports** in SARIF, JSON, Markdown, and HTML formats
- ✍️ YAML-based custom rule definition
- ✅ Zero-config startup with smart defaults

---

## 🛠️ Installation

```bash
go install github.com/YOUR_ORG/codexsentinel/cmd/codex@latest
```

Or use the install script:

```bash
curl -sSfL https://raw.githubusercontent.com/YOUR_ORG/codexsentinel/main/scripts/install.sh | sh
```

## 📦 Usage

```bash
codex scan ./...
```

**Optional flags:**

| Flag            | Description                                       |
| --------------- | ------------------------------------------------- |
| `--config`      | Path to `.codex.yml` config file                  |
| `--output`      | Output report file path                           |
| `--format`      | Report format:`json`, `html`, `sarif`, `markdown` |
| `--severity`    | Minimum severity to report (`low`-`critical`)     |
| `--ignore-file` | Path to `.codexsentinel.ignore`                   |

## 📁 Project Structure

```
codexsentinel/
├── analyzer/        # Core analyzers (AST, SSA, Taint, Rules)
├── deps/            # Dependency & license scanners
├── metrics/         # Complexity, duplication, dead code
├── arch/            # Architecture layer rules
├── report/          # Report generation (HTML, SARIF, etc.)
├── cmd/             # CLI entrypoints
├── internal/        # Internal utils (logging, config, fs)
├── testdata/        # Example test files with issues
└── assets/          # Rules, templates, CSS, etc.
```

## 📚 Example

```go
// insecure_sql.go
query := "SELECT * FROM users WHERE id = " + id
db.Query(query) // ❌ Vulnerable to SQL Injection
```

```bash
codex scan ./testdata/insecure_sql.go --format markdown
```

## 📘 Custom Rules

Write custom YAML rules and place them under `assets/rules/`.

```yaml
id: go.insecure.xss.reflected_input
pattern: "w.Write([]byte({{input}}))"
filters:
  - type: param
    sources: [r.FormValue]
```

Learn more in `assets/rules/`.

## 🧪 Testing

```bash
go test ./...
```

## 📄 License

MIT © [Voskan](https://github.com/Voskan) - see the [LICENSE](LICENSE) file for details.

## 🧠 Related Links

- [Go SSA Documentation](https://pkg.go.dev/golang.org/x/tools/go/ssa)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## 💬 Contributing

We welcome PRs and new rule contributions. Please follow our contribution guide and ensure all changes are covered by tests.

## ✨ Example Report

```yaml
---
version: "0.1.0"
timestamp: "2024-01-01T12:00:00Z"
issues:
  - id: "SEC001"
    name: "SQL Injection"
    description: "Potential SQL injection vulnerability detected"
    severity: "high"
    location:
      file: "main.go"
      line: 42
      column: 10
    category: "security"
    rule_id: "go.insecure.sql_injection"
---
```
