# CodexSentinel Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Installation

```bash
# Install CodexSentinel
go install github.com/Voskan/codexsentinel/cmd/codex@latest

# Verify installation
codex version
```

### 2. Your First Scan

```bash
# Scan current directory
codex scan .

# Scan specific project
codex scan /path/to/your/go/project
```

### 3. View Results

```bash
# JSON output
codex scan . --format json --out results.json

# Markdown report
codex scan . --format markdown --out report.md

# HTML report
codex scan . --format html --out report.html
```

### 4. Advanced Scanning

```bash
# Comprehensive analysis
codex scan . --enable-ssa --enable-taint --verbose

# Exclude directories
codex scan . --exclude vendor,node_modules,testdata

# Custom rules
codex scan . --rules my-custom-rules.yaml
```

## 📋 What CodexSentinel Detects

### Security Vulnerabilities

- ✅ **SQL Injection** - Unsafe query construction
- ✅ **XSS** - Cross-site scripting vulnerabilities
- ✅ **CSRF** - Cross-site request forgery
- ✅ **SSRF** - Server-side request forgery
- ✅ **Path Traversal** - Directory traversal attacks
- ✅ **Command Injection** - Unsafe command execution
- ✅ **Weak Crypto** - Insecure cryptographic algorithms
- ✅ **Auth Bypass** - Authentication bypass patterns
- ✅ **Session Issues** - Session management problems
- ✅ **API Security** - API security misconfigurations
- ✅ **GraphQL Security** - GraphQL-specific vulnerabilities
- ✅ **JWT Security** - JWT token security issues
- ✅ **WebSocket Security** - WebSocket security problems

### Code Quality Issues

- ✅ **High Complexity** - Overly complex functions
- ✅ **Code Duplication** - Duplicate code blocks
- ✅ **Large Functions** - Functions that are too large
- ✅ **Dead Code** - Unused code detection
- ✅ **Global Variables** - Global state analysis

### Dependency Issues

- ✅ **Vulnerable Dependencies** - Known security vulnerabilities
- ✅ **License Issues** - License compliance problems
- ✅ **High Entropy** - Suspicious files detection

## 🛡️ OWASP Top 10 2025 Coverage

| Category | Status  | Description               |
| -------- | ------- | ------------------------- |
| A01:2025 | ✅ Full | Broken Access Control     |
| A02:2025 | ✅ Full | Cryptographic Failures    |
| A03:2025 | ✅ Full | Injection                 |
| A04:2025 | ✅ Full | Insecure Design           |
| A05:2025 | ✅ Full | Security Misconfiguration |
| A06:2025 | ✅ Full | Vulnerable Components     |
| A07:2025 | ✅ Full | Authentication Failures   |
| A08:2025 | ✅ Full | Data Integrity Failures   |
| A09:2025 | ✅ Full | Logging Failures          |
| A10:2025 | ✅ Full | SSRF                      |

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

### CI/CD Integration

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

## 📚 Next Steps

1. **Read the Full Documentation**: [Wiki Documentation](WIKI_DOCUMENTATION.md)
2. **Explore Advanced Features**: Custom rules, CI/CD integration
3. **Join the Community**: [GitHub Discussions](https://github.com/Voskan/codexsentinel/discussions)
4. **Report Issues**: [GitHub Issues](https://github.com/Voskan/codexsentinel/issues)
5. **Get Support**: [voskan1989@gmail.com](mailto:voskan1989@gmail.com)

## 🎯 Pro Tips

- **Regular Scans**: Run security scans on every commit
- **Custom Rules**: Create project-specific security rules
- **Team Training**: Educate your team on security best practices
- **Stay Updated**: Keep CodexSentinel updated for latest security rules
- **Integration**: Integrate with your existing CI/CD pipeline

---

_Ready to secure your Go codebase? Start scanning now!_ 🚀
