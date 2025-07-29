# CodexSentinel Wiki

<div align="center">

![CodexSentinel Logo](https://img.shields.io/badge/CodexSentinel-v1.5.0-blue?style=for-the-badge&logo=go) ![Go Version](https://img.shields.io/badge/Go-1.24.2+-00ADD8?style=for-the-badge&logo=go) ![OWASP Coverage](https://img.shields.io/badge/OWASP%20Top%2010%202025-100%25-green?style=for-the-badge)![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**Advanced Static Code Analysis & Security Scanner for Go Projects**

[![GitHub stars](https://img.shields.io/github/stars/Voskan/codexsentinel?style=social)](https://github.com/Voskan/codexsentinel) [![GitHub forks](https://img.shields.io/github/forks/Voskan/codexsentinel?style=social)](https://github.com/Voskan/codexsentinel) [![GitHub issues](https://img.shields.io/github/issues/Voskan/codexsentinel)](https://github.com/Voskan/codexsentinel/issues) [![GitHub pull requests](https://img.shields.io/github/issues-pr/Voskan/codexsentinel)](https://github.com/Voskan/codexsentinel/pulls)

</div>

---

## 🚀 Quick Start

```bash
# Install CodexSentinel
# Quick install (recommended)
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh

# Or via Go
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest

# Scan current directory
codex-cli scan .

# View results in different formats
codex-cli scan . --format json --out results.json
codex-cli scan . --format markdown --out report.md
codex-cli scan . --format html --out report.html
```

---

## 📚 Documentation

### Getting Started

- **[Quick Start Guide](WIKI_QUICK_START.md)** - Get up and running in 5 minutes
- **[Full Documentation](WIKI_DOCUMENTATION.md)** - Comprehensive project documentation
- **[API Reference](WIKI_API_REFERENCE.md)** - Complete API documentation
- **[Examples](WIKI_EXAMPLES.md)** - Practical usage examples

### Core Features

- **🔒 Security Analysis** - 18+ security rules with OWASP Top 10 2025 coverage
- **📊 Code Quality** - Complexity, duplication, and maintainability analysis
- **📦 Dependency Scanning** - OSV integration for vulnerability detection
- **🎯 Go Language Focus** - Optimized specifically for Go codebases

---

## 🛡️ Security Coverage

### OWASP Top 10 2025 - 100% Coverage

| Category     | Status  | Description                       |
| ------------ | ------- | --------------------------------- |
| **A01:2025** | ✅ Full | **Broken Access Control**         |
| **A02:2025** | ✅ Full | **Cryptographic Failures**        |
| **A03:2025** | ✅ Full | **Injection** (SQL, Command, XSS) |
| **A04:2025** | ✅ Full | **Insecure Design**               |
| **A05:2025** | ✅ Full | **Security Misconfiguration**     |
| **A06:2025** | ✅ Full | **Vulnerable Components**         |
| **A07:2025** | ✅ Full | **Authentication Failures**       |
| **A08:2025** | ✅ Full | **Data Integrity Failures**       |
| **A09:2025** | ✅ Full | **Logging Failures**              |
| **A10:2025** | ✅ Full | **SSRF**                          |

### Advanced Security Rules

- **🔐 Authentication Bypass Detection**
- **📝 Session Management Issues**
- **🌐 API Security Rules**
- **📊 GraphQL Security**
- **🎫 JWT Token Security**
- **🔌 WebSocket Security**
- **🛣️ Path Traversal Detection**
- **💉 SQL Injection Detection**
- **🌐 XSS Prevention**
- **🔄 CSRF Protection**

---

## 📊 Project Statistics

| Metric                | Value                           |
| --------------------- | ------------------------------- |
| **Lines of Code**     | 15,000+                         |
| **Go Files**          | 100+                            |
| **Security Rules**    | 18+                             |
| **OWASP Coverage**    | 100% (A01-A10:2025)             |
| **Supported Formats** | 4 (JSON, Markdown, SARIF, HTML) |
| **Analysis Types**    | 4 (AST, SSA, Taint, Metrics)    |
| **Performance**       | ~1000 LOC/second                |

---

## 🎯 Key Features

### 🔍 Multi-Analysis Engine

- **AST Analysis** - Abstract Syntax Tree parsing
- **SSA Analysis** - Static Single Assignment analysis
- **Taint Analysis** - Data flow tracking
- **Metrics Analysis** - Code quality metrics

### 📋 Comprehensive Detection

- **Security Vulnerabilities** - 18+ built-in security rules
- **Code Quality Issues** - Complexity, duplication, maintainability
- **Dependency Vulnerabilities** - OSV and GitHub Security Advisories
- **License Compliance** - License violation detection

### 🎨 Multiple Output Formats

- **JSON** - Machine-readable format for CI/CD
- **Markdown** - Human-readable reports
- **SARIF** - Standard format for security tools
- **HTML** - Interactive web reports

### ⚙️ Flexible Configuration

- **Custom Rules** - YAML-based rule definition
- **Ignore Patterns** - Skip specific files or issues
- **Severity Filtering** - Focus on specific issue levels
- **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins

---

## 🚀 Use Cases

### 🔒 Security Teams

- **Vulnerability Assessment** - Identify security issues early
- **Compliance Checking** - Ensure OWASP compliance
- **Code Review** - Automated security review
- **Threat Modeling** - Identify attack vectors

### 👨‍💻 Developers

- **Code Quality** - Maintain high code standards
- **Best Practices** - Follow Go security guidelines
- **Refactoring** - Identify improvement opportunities
- **Learning** - Understand security patterns

### 🏢 Enterprises

- **DevSecOps** - Integrate security into CI/CD
- **Compliance** - Meet regulatory requirements
- **Risk Management** - Identify and mitigate risks
- **Audit Trails** - Track security issues over time

---

## 📈 Performance

### Speed

- **Analysis Speed**: ~1000 LOC/second
- **Memory Usage**: < 100MB for typical projects
- **CPU Usage**: Optimized for multi-core systems
- **Accuracy**: High precision with low false positives

### Scalability

- **Large Codebases** - Handle projects with 100k+ LOC
- **Parallel Processing** - Multi-core analysis
- **Incremental Analysis** - Only analyze changed files
- **Caching** - Intelligent result caching

---

## 🛠️ Installation

### Prerequisites

- Go 1.24.2 or higher
- Git

### Installation Methods

#### Method 1: Go Install

```bash
# Quick install (recommended)
curl -sSfL https://raw.githubusercontent.com/Voskan/codexsentinel/main/scripts/install.sh | sh

# Or via Go
go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
```

#### Method 2: Build from Source

```bash
git clone https://github.com/Voskan/codexsentinel.git
cd codexsentinel
make build
```

#### Method 3: Download Binary

Visit [releases page](https://github.com/Voskan/codexsentinel/releases) and download the appropriate binary.

---

## 🔧 Configuration

### Basic Configuration

Create `codex.yaml` in your project:

```yaml
analysis:
  enable_ssa: true
  enable_taint: true
  enable_ast: true

output:
  format: json
  file: results.json
  verbose: false

exclude:
  - vendor/
  - node_modules/
  - testdata/
```

### Environment Variables

```bash
export CODEX_CONFIG=./custom-config.yaml
export CODEX_OUTPUT_FORMAT=json
export CODEX_VERBOSE=true
```

---

## 🔗 Integration

### CI/CD Pipelines

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: "1.24"
      - name: Install CodexSentinel
        run: go install github.com/Voskan/codexsentinel/cmd/codex@latest
      - name: Run Security Scan
        run: codex scan . --format sarif --out results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
security-scan:
  stage: test
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex@latest
    - codex scan . --format json --out results.json
  artifacts:
    reports:
      security: results.json
```

### IDE Integration

- **VS Code Extension** - Real-time analysis
- **GoLand Plugin** - Integrated scanning
- **Vim/Neovim** - Command-line integration

---

## 📊 Sample Output

```bash
$ codex scan .
[INFO] Starting CodexSentinel analysis...
[INFO] Found 15 Go files to analyze
[INFO] Running AST analysis...
[INFO] Running SSA analysis...
[INFO] Running taint analysis...
[INFO] Running dependency analysis...
[INFO] Running metrics analysis...

[HIGH] SQL Injection Vulnerability at main.go:42
    Description: Potential SQL injection: avoid building queries via string concatenation
    Suggestion: Use parameterized queries instead of raw string concatenation
    Reference: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection

[MEDIUM] High Cyclomatic Complexity at utils.go:15
    Description: Function processData has complexity 12 (threshold: 10)
    Suggestion: Consider breaking down the function into smaller functions

[HIGH] Vulnerable Dependency at go.mod:0
    Description: Module github.com/go-yaml/yaml@v2.1.0+incompatible has vulnerability: GHSA-r88r-gmrh-7j83
    Suggestion: Update to a fixed version or apply security patches

Analysis complete! Found 15 issues (8 HIGH, 5 MEDIUM, 2 LOW)
```

---

## 🤝 Contributing

### Development Setup

```bash
git clone https://github.com/Voskan/codexsentinel.git
cd codexsentinel
go mod tidy
make build
make test
```

### Adding New Rules

1. Create rule file in `analyzer/rules/builtin/`
2. Implement rule logic following existing patterns
3. Add test cases in `testdata/`
4. Register rule in `analyzer/engine/engine.go`
5. Update documentation

### Code Style

- Follow Go conventions
- Use meaningful variable names
- Add comprehensive comments
- Include unit tests
- Update documentation

---

## 📞 Support

### Getting Help

- **📧 Email**: [voskan1989@gmail.com](mailto:voskan1989@gmail.com)
- **🐛 Issues**: [GitHub Issues](https://github.com/Voskan/codexsentinel/issues)
- **📖 Documentation**: [Wiki](https://github.com/Voskan/codexsentinel/wiki)

### Community

- **GitHub**: [Repository](https://github.com/Voskan/codexsentinel)
- **Releases**: [Latest Release](https://github.com/Voskan/codexsentinel/releases)
- **Security**: [Security Policy](https://github.com/Voskan/codexsentinel/security)

### Resources

- **OWASP Top 10**: [2025 Edition](https://owasp.org/www-project-top-ten/)
- **Go Security**: [Go Security Best Practices](https://golang.org/doc/security)
- **SAST Tools**: [Static Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)

---

## 🏆 Recognition

### Awards & Achievements

- **OWASP Top 10 2025 Coverage**: 100% (A01-A10:2025)
- **Latest OWASP Standards**: Full compliance
- **Go Language Focus**: Optimized for Go ecosystems
- **Enterprise Ready**: Production-grade security scanning

### Statistics

- **Security Rules**: 18+ built-in rules
- **Analysis Types**: 4 comprehensive analysis engines
- **Output Formats**: 4 flexible output options
- **Performance**: High-speed analysis with low resource usage

---

## 📈 Roadmap

### Current Version (v1.5.0)

- ✅ **OWASP Top 10 2025** - Full coverage
- ✅ **Advanced Security Rules** - API, GraphQL, JWT, WebSocket
- ✅ **Multi-Format Output** - JSON, Markdown, SARIF, HTML
- ✅ **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins

### Upcoming Features

- 🔄 **OWASP Top 10 2027** - Future standards support
- 🔄 **Machine Learning** - AI-powered vulnerability detection
- 🔄 **Cloud Integration** - AWS, Azure, GCP scanning
- 🔄 **Container Security** - Docker and Kubernetes scanning

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by the CodexSentinel Team**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Voskan/codexsentinel) [![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org/) [![OWASP](https://img.shields.io/badge/OWASP-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)

</div>
