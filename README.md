# 🛡️ CodexSentinel

[![Go Version](https://img.shields.io/badge/Go-1.24.2+-blue.svg)](https://golang.org/) [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-brightgreen.svg)](https://slsa.dev/) [![Go Report Card](https://goreportcard.com/badge/github.com/Voskan/codexsentinel)](https://goreportcard.com/report/github.com/Voskan/codexsentinel) [![Go Reference](https://pkg.go.dev/badge/github.com/Voskan/codexsentinel.svg)](https://pkg.go.dev/github.com/Voskan/codexsentinel) [![Release](https://img.shields.io/github/v/release/Voskan/codexsentinel?include_prereleases&sort=semver)](https://github.com/Voskan/codexsentinel/releases)

**CodexSentinel** is a powerful, blazing-fast static code analyzer for **Go**, built to identify security vulnerabilities, bad practices, architectural violations, and dependency risks. Designed for developers, DevSecOps, and auditors, it supports both CLI usage and structured JSON reports for integration with CI/CD pipelines.

## 📋 Table of Contents

- [🚀 Features](#-features)
- [📦 Installation](#-installation-and-usage-all-os)
- [🔧 Usage](#-usage)
- [📁 Project Structure](#-project-structure)
- [📚 Examples](#-examples)
- [📘 Custom Rules](#-custom-rules)
- [🧪 Testing](#-testing)
- [🔄 CI/CD Integration](#-cicd-integration)
- [📄 License](#-license)
- [🧠 Related Links](#-related-links)
- [💬 Contributing](#-contributing)
- [✨ Example Reports](#-example-reports)

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
- 📁 **Individual file analysis** - scan files with different package names
- 🛡️ **Graceful error handling** - continues analysis even with package conflicts
- 📂 **Automatic report organization** - saves reports to `scan_reports/` directory
- 🔐 **SLSA Level 3** compliant releases for supply chain security

---

## 📦 Installation and Usage (All OS)

### 🎯 Quick Install (Recommended)

```bash
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh
```

This script will:

- Download the latest binary for your OS
- Install it globally (add to PATH)
- Create a convenient `codex` alias
- Work on Linux, macOS, and Windows (via Git Bash/WSL)

### 🔧 Manual Install via Go

```bash
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
```

### 📍 Where to find the binary

- By default, Go installs the binary as **codex-cli** in:
  - **Linux/macOS:** `$HOME/go/bin/`
  - **Windows:** `%USERPROFILE%\go\bin\`

### 🌐 Make codex-cli globally available

#### Linux/macOS:

```bash
# Add to PATH permanently
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc

# Reload shell configuration
source ~/.bashrc  # or source ~/.zshrc

# Now you can run from anywhere:
codex-cli version
```

#### Windows (PowerShell):

```powershell
# Add to PATH permanently
$goBinPath = "$env:USERPROFILE\go\bin"
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "$currentPath;$goBinPath", "User")

# Reload environment variables
refreshenv  # if you have Chocolatey installed
# or restart your terminal

# Now you can run from anywhere:
codex-cli version
```

#### Windows (Command Prompt):

```cmd
# Add to PATH permanently
setx PATH "%PATH%;%USERPROFILE%\go\bin"

# Restart your terminal, then run:
codex-cli version
```

### ⚡ (Optional) Create a shorter alias

#### Linux/macOS:

```bash
# Add alias to your shell config
echo 'alias codex="codex-cli"' >> ~/.bashrc
echo 'alias codex="codex-cli"' >> ~/.zshrc

# Reload and use:
source ~/.bashrc  # or source ~/.zshrc
codex version
```

#### Windows (PowerShell):

```powershell
# Add to PowerShell profile
echo 'Set-Alias codex codex-cli' >> $PROFILE

# Reload and use:
. $PROFILE
codex version
```

### ✅ Verify installation

```bash
# Should work from any directory:
codex-cli version
```

---

## 📦 Usage

### 🔍 Basic Scan

```bash
# Scan current directory
codex-cli scan .

# Scan specific file
codex-cli scan ./main.go

# Scan specific directory
codex-cli scan ./pkg/

# Scan with custom output
codex-cli scan . --format html --out report.html

# Scan individual files (even with different package names)
codex-cli scan testdata/command_injection.go
codex-cli scan testdata/xss_vulnerability.go
```

### ⚙️ Advanced Usage

```bash
# Scan with specific severity
codex-cli scan . --severity high

# Use custom config
codex-cli scan . --config .codex.yml

# Ignore specific files
codex-cli scan . --ignore-file .codexsentinel.ignore

# Generate SARIF for CI/CD
codex-cli scan . --format sarif --out results.sarif

# Generate HTML report (saved to scan_reports/)
codex-cli scan . --format html --out report.html

# Generate JSON report (saved to scan_reports/)
codex-cli scan . --format json --out report.json

# Run dependency analysis only
codex-cli scan . --deps

# Filter by severity (high and above)
codex-cli scan . --severity high

# Use custom config file
codex-cli scan . --config custom-config.yml
```

### 📋 Available Flags

| Flag            | Description                                                   | Default                              |
| --------------- | ------------------------------------------------------------- | ------------------------------------ |
| `-p, --path`    | Target directory or file to scan                              | `.` (current directory)              |
| `-f, --format`  | Output report format:`sarif`, `html`, `markdown`, `json`      | `sarif`                              |
| `-o, --out`     | Path to write the output report to                            | `scan_reports/codex-report.{format}` |
| `--strict`      | Exit with code 1 if issues are found                          | `false`                              |
| `--ignore-file` | Path to ignore file                                           | `.codexsentinel.ignore`              |
| `--deps`        | Run dependency analysis only                                  | `false`                              |
| `--config`      | Path to a custom config file                                  | `.codex.yml` (if exists)             |
| `--severity`    | Filter issues by severity:`low`, `medium`, `high`, `critical` | `all` (no filtering)                 |

### 📄 Report Output

Reports are automatically saved to the `scan_reports/` directory:

- HTML reports: `scan_reports/codex-report.html`
- JSON reports: `scan_reports/codex-report.json`
- SARIF reports: `scan_reports/codex-report.sarif`
- Markdown reports: `scan_reports/codex-report.md`

The directory is created automatically if it doesn't exist.

---

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
├── testdata/        # Example test files with security vulnerabilities
│   ├── command_injection.go    # Command injection examples
│   ├── xss_vulnerability.go    # XSS vulnerability examples
│   ├── sql_injection.go        # SQL injection examples
│   └── path_traversal.go       # Path traversal examples
└── assets/          # Rules, templates, CSS, etc.
```

---

## 📚 Examples

### 🔒 Security Vulnerabilities

**SQL Injection:**

```go
// ❌ Vulnerable
query := "SELECT * FROM users WHERE id = " + userInput
db.Query(query)

// ✅ Safe
query := "SELECT * FROM users WHERE id = ?"
db.Query(query, userInput)
```

**Command Injection:**

```go
// ❌ Vulnerable
cmd := exec.Command("sh", "-c", userInput)
cmd.Run()

// ✅ Safe
cmd := exec.Command("echo", userInput)
cmd.Run()
```

**XSS (Cross-Site Scripting):**

```go
// ❌ Vulnerable
w.Write([]byte(userInput))

// ✅ Safe
w.Write([]byte(html.EscapeString(userInput)))
```

### 🏗️ Architecture Violations

**Direct Layer Calls:**

```go
// ❌ Handler directly calling repository
func (h *Handler) GetUser(id string) {
    user := h.repo.GetUser(id) // Direct call to repo layer
}

// ✅ Handler calling service layer
func (h *Handler) GetUser(id string) {
    user := h.service.GetUser(id) // Proper layer separation
}
```

### 🔍 Running Analysis

```bash
# Scan for security issues
codex-cli scan ./... --strict

# Generate HTML report
codex-cli scan ./... --format html --out security-report.html

# Check architecture compliance
codex-cli scan ./... --config .codex.yml

# Scan test files with vulnerabilities
codex-cli scan testdata/
```

---

## 📘 Custom Rules

Create custom YAML rules and place them under `assets/rules/`.

```yaml
id: go.insecure.xss.reflected_input
title: "XSS via Reflected Input"
category: "security"
severity: "high"
pattern: "w.Write([]byte({{input}}))"
filters:
  - type: param
    sources: [r.FormValue, r.URL.Query]
description: "Potential XSS vulnerability when writing user input directly to response"
suggestion: "Use html.EscapeString() to sanitize user input"
```

### 📋 Rule Structure

```yaml
id: "unique.rule.identifier"
title: "Human readable title"
category: "security|style|performance"
severity: "low|medium|high|critical"
pattern: "Go AST pattern to match"
filters:
  - type: "param|call|import"
    sources: ["list", "of", "sources"]
description: "Detailed description of the issue"
suggestion: "How to fix the issue"
references:
  - "https://owasp.org/..."
```

Learn more in `assets/rules/`.

---

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test ./analyzer/...
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.24"

      - name: Install CodexSentinel
        run: go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest

      - name: Run Security Scan
        run: codex-cli scan ./... --format sarif --out results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
    - codex-cli scan ./... --format sarif --out results.sarif
  artifacts:
    reports:
      sarif: results.sarif
```

---

## 📄 License

MIT © [Voskan](https://github.com/Voskan) - see the [LICENSE](LICENSE) file for details.

---

## 🧠 Related Links

- [Go SSA Documentation](https://pkg.go.dev/golang.org/x/tools/go/ssa)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SLSA Framework](https://slsa.dev/)

---

## 💬 Contributing

We welcome PRs and new rule contributions. Please follow our contribution guide and ensure all changes are covered by tests.

### 🤝 How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### 📝 Development Setup

```bash
# Clone the repository
git clone https://github.com/Voskan/codexsentinel.git
cd codexsentinel

# Install dependencies
go mod download

# Run tests
go test ./...

# Build the binary
go build -o codex ./cmd/codex-cli
```

---

## ✨ Example Reports

### 📊 JSON Report

```json
{
  "version": "0.1.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "issues": [
    {
      "id": "SEC001",
      "title": "SQL Injection",
      "description": "Potential SQL injection vulnerability detected",
      "severity": "high",
      "location": {
        "file": "main.go",
        "line": 42,
        "column": 10
      },
      "category": "security",
      "rule_id": "go.insecure.sql_injection",
      "suggestion": "Use parameterized queries"
    }
  ]
}
```

### 🔍 SARIF Report (for CI/CD)

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodexSentinel",
          "version": "1.0.0"
        }
      },
      "results": [
        {
          "ruleId": "go.insecure.sql_injection",
          "level": "error",
          "message": {
            "text": "Potential SQL injection vulnerability"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "main.go"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 10
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 🔐 SLSA Level 3 Compliance

CodexSentinel releases are built with SLSA Level 3 compliance, ensuring:

- ✅ **Provenance**: Every release includes a provenance file describing the build process
- ✅ **Verification**: Anyone can verify that binaries were built from expected source code
- ✅ **Reproducibility**: Builds are reproducible and verifiable
- ✅ **Supply Chain Security**: Protection against supply chain attacks

### 🔍 Verifying Releases

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify a release
slsa-verifier verify-artifact \
  --provenance-path codex-linux-amd64.intoto.jsonl \
  --source-uri github.com/Voskan/codexsentinel \
  --source-tag v1.0.0 \
  codex-linux-amd64
```

---

## 📈 Release History

### Latest Release: [v1.0.0](https://github.com/Voskan/codexsentinel/releases/latest)

**Features:**

- 🆕 Initial release with comprehensive security scanning
- 🔍 OWASP Top 10 vulnerability detection
- 📦 Dependency analysis with OSV integration
- 🏗️ Architecture compliance checking
- 📊 Multiple report formats (SARIF, JSON, HTML, Markdown)
- 🔐 SLSA Level 3 compliant releases

**Supported Platforms:**

- 🐧 Linux (AMD64, ARM64)
- 🍎 macOS (AMD64, ARM64)
- 🪟 Windows (AMD64, ARM64)

**Download:** [Latest Release](https://github.com/Voskan/codexsentinel/releases/latest)

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Voskan/codexsentinel&type=Date)](https://star-history.com/#Voskan/codexsentinel&Date)

---

## 📊 Project Statistics

![GitHub stats](https://github-readme-stats.vercel.app/api?username=Voskan&show_icons=true&theme=radical)

![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=Voskan&layout=compact&theme=radical)

---

## 🎯 Roadmap

- [ ] 🔍 Enhanced taint analysis with more precise data flow tracking
- [ ] 📊 Advanced code metrics and visualization
- [ ] 🔧 IDE integration (VS Code, GoLand extensions)
- [ ] 🌐 Web-based dashboard for analysis results
- [ ] 📚 Comprehensive rule library expansion
- [ ] 🔄 Real-time monitoring and alerting
- [ ] 🧪 Integration with more CI/CD platforms
- [ ] 📱 Mobile app for quick scans

---

## 🤝 Support

- 📧 **Email**: [support@codexsentinel.dev](mailto:support@codexsentinel.dev)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Voskan/codexsentinel/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/Voskan/codexsentinel/issues)
- 📖 **Documentation**: [Wiki](https://github.com/Voskan/codexsentinel/wiki)

---

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines
- [Go Team](https://golang.org/) for the amazing language
- [SLSA Framework](https://slsa.dev/) for supply chain security
- All contributors and users of CodexSentinel

---

<div align="center">

**Made with ❤️ by the CodexSentinel Team**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Voskan/codexsentinel)
[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/)
[![Security](https://img.shields.io/badge/Security-000000?style=for-the-badge&logo=security&logoColor=white)](https://slsa.dev/)

</div>
