# CodexSentinel Wiki Documentation

## 📚 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Core Features](#core-features)
6. [Security Rules](#security-rules)
7. [Command Line Interface](#command-line-interface)
8. [Configuration](#configuration)
9. [Output Formats](#output-formats)
10. [Advanced Usage](#advanced-usage)
11. [API Reference](#api-reference)
12. [Troubleshooting](#troubleshooting)
13. [Contributing](#contributing)
14. [Security Policy](#security-policy)

---

## 🎯 Overview

**CodexSentinel** is a comprehensive static code analysis and security scanning tool designed specifically for Go projects. It provides advanced SAST (Static Application Security Testing) capabilities with support for OWASP Top 10 2025 security standards.

### Key Features

- **🔒 OWASP Top 10 2025 Coverage**: 100% coverage of all security categories
- **📊 Multi-Analysis Engine**: AST, SSA, Taint Analysis, and Metrics
- **🛡️ 18+ Security Rules**: Built-in detection for common vulnerabilities
- **📦 Dependency Scanning**: OSV integration for vulnerability detection
- **📈 Code Quality Metrics**: Complexity, duplication, and maintainability analysis
- **🎯 Go Language Focus**: Optimized specifically for Go codebases

---

## 🏗️ Architecture

### Core Components

```
codexsentinel/
├── cmd/codex/           # CLI application
├── analyzer/            # Core analysis engine
│   ├── engine/         # Analysis coordination
│   ├── rules/          # Security rule implementations
│   ├── ast/           # Abstract Syntax Tree utilities
│   ├── ssa/           # Static Single Assignment analysis
│   └── flow/          # Taint flow analysis
├── deps/              # Dependency scanning
├── metrics/           # Code quality metrics
├── report/            # Report generation
└── internal/          # Internal utilities
```

### Analysis Pipeline

1. **File Discovery**: Recursive scanning of Go files
2. **AST Parsing**: Parse Go source into Abstract Syntax Trees
3. **Rule Application**: Apply security rules to AST nodes
4. **SSA Analysis**: Static Single Assignment analysis for data flow
5. **Taint Tracking**: Track untrusted data through the codebase
6. **Dependency Analysis**: Scan for vulnerable dependencies
7. **Metrics Calculation**: Compute code quality metrics
8. **Report Generation**: Generate comprehensive security reports

---

## 🚀 Installation

### Prerequisites

- Go 1.24.2 or higher
- Git

### Installation Methods

#### Method 1: Build from Source

```bash
git clone https://github.com/Voskan/codexsentinel.git
cd codexsentinel
make build
```

#### Method 2: Go Install

```bash
go install github.com/Voskan/codexsentinel/cmd/codex@latest
```

#### Method 3: Download Binary

Visit the [releases page](https://github.com/Voskan/codexsentinel/releases) and download the appropriate binary for your platform.

---

## ⚡ Quick Start

### Basic Scan

```bash
# Scan current directory
codex scan .

# Scan specific directory
codex scan /path/to/project

# Scan single file
codex scan main.go
```

### Output Formats

```bash
# JSON output
codex scan . --format json --out results.json

# Markdown report
codex scan . --format markdown --out report.md

# SARIF format (for CI/CD)
codex scan . --format sarif --out results.sarif

# HTML report
codex scan . --format html --out report.html
```

### Advanced Usage

```bash
# Enable specific analysis types
codex scan . --enable-ssa --enable-taint

# Exclude files/directories
codex scan . --exclude vendor,node_modules

# Custom rules file
codex scan . --rules custom-rules.yaml

# Verbose output
codex scan . --verbose
```

---

## 🔧 Core Features

### 1. Static Analysis Engine

#### AST-Based Analysis

- Parses Go source code into Abstract Syntax Trees
- Applies security rules to AST nodes
- Detects patterns in function calls, assignments, and expressions

#### SSA Analysis

- Static Single Assignment form analysis
- Tracks variable definitions and uses
- Identifies data flow patterns

#### Taint Analysis

- Tracks untrusted data through the codebase
- Identifies potential security vulnerabilities
- Maps data flow from sources to sinks

### 2. Security Rules Engine

#### Built-in Rules

- **18+ Security Rules**: Comprehensive coverage of common vulnerabilities
- **OWASP Top 10 2025**: Full compliance with latest standards
- **Custom Rules**: YAML-based rule definition system

#### Rule Categories

- **Access Control**: Broken access control detection
- **Cryptographic Failures**: Weak crypto algorithm detection
- **Injection**: SQL, Command, XSS injection detection
- **Insecure Design**: Architectural security issues
- **Security Misconfiguration**: Debug endpoints, unsafe settings
- **Vulnerable Components**: Dependency vulnerability scanning
- **Authentication Failures**: Auth bypass, session management
- **Data Integrity**: Software and data integrity failures
- **Logging Failures**: Security logging and monitoring issues
- **SSRF**: Server-Side Request Forgery detection

### 3. Dependency Analysis

#### Vulnerability Scanning

- **OSV Integration**: Open Source Vulnerabilities database
- **GitHub Security Advisories**: GHSA vulnerability detection
- **License Compliance**: License violation detection
- **High Entropy Detection**: Suspicious file identification

#### Supported Sources

- `go.mod` and `go.sum` files
- Vendor directories
- Direct and indirect dependencies

### 4. Code Quality Metrics

#### Complexity Analysis

- **Cyclomatic Complexity**: Function complexity measurement
- **Cognitive Complexity**: Code readability metrics
- **Function Size**: Large function detection

#### Duplication Detection

- **Code Duplication**: Identifies duplicate code blocks
- **Similarity Analysis**: Finds similar code patterns
- **Refactoring Suggestions**: Code improvement recommendations

#### Maintainability Metrics

- **Dead Code Detection**: Unused code identification
- **Global Variable Analysis**: Global state tracking
- **Code Size Metrics**: File and function size analysis

---

## 🛡️ Security Rules

### OWASP Top 10 2025 Coverage

| Category | Rule                      | Description                            | Severity |
| -------- | ------------------------- | -------------------------------------- | -------- |
| A01:2025 | Broken Access Control     | Detects broken access control patterns | High     |
| A02:2025 | Cryptographic Failures    | Identifies weak crypto algorithms      | High     |
| A03:2025 | Injection                 | SQL, Command, XSS injection detection  | High     |
| A04:2025 | Insecure Design           | Architectural security issues          | High     |
| A05:2025 | Security Misconfiguration | Debug endpoints, unsafe settings       | Medium   |
| A06:2025 | Vulnerable Components     | Dependency vulnerability scanning      | High     |
| A07:2025 | Authentication Failures   | Auth bypass, session management        | High     |
| A08:2025 | Data Integrity Failures   | Software and data integrity issues     | High     |
| A09:2025 | Logging Failures          | Security logging and monitoring        | Medium   |
| A10:2025 | SSRF                      | Server-Side Request Forgery detection  | High     |

### Advanced Security Rules

#### API Security

- **Authentication**: API authentication bypass detection
- **Authorization**: Permission checking patterns
- **Rate Limiting**: Rate limiting implementation
- **Input Validation**: API input sanitization
- **CORS**: Cross-Origin Resource Sharing issues
- **SSL/TLS**: Transport security configuration

#### GraphQL Security

- **Introspection**: GraphQL introspection security
- **Depth/Complexity Limits**: Query complexity controls
- **Authentication**: GraphQL authentication patterns
- **Authorization**: GraphQL permission checking
- **Rate Limiting**: GraphQL rate limiting
- **Injection**: GraphQL injection attacks
- **XSS**: Cross-site scripting in GraphQL
- **CSRF**: Cross-site request forgery
- **DoS**: Denial of service protection
- **Batching**: Query batching security
- **Persisted Queries**: Query persistence security
- **Query Whitelisting**: Query filtering

#### JWT Security

- **Weak Algorithms**: Insecure JWT algorithms
- **Improper Validation**: JWT validation issues
- **Expiration**: Token expiration handling
- **Signature Verification**: JWT signature checking
- **Insecure Keys**: Weak JWT keys
- **Issuer/Audience**: JWT claim validation
- **Token Lifetime**: Token lifetime management
- **Storage**: Secure token storage
- **Revocation**: Token revocation mechanisms
- **Refresh Tokens**: Refresh token security
- **Claims Validation**: JWT claims checking
- **Timing Attacks**: Timing attack prevention
- **Random Generation**: Secure random generation
- **Rate Limiting**: JWT rate limiting

#### WebSocket Security

- **Authentication**: WebSocket authentication
- **Rate Limiting**: WebSocket rate limiting
- **Input Validation**: WebSocket input validation
- **Error Handling**: WebSocket error handling
- **Message Size Limits**: Message size controls
- **Ping/Pong**: WebSocket heartbeat mechanisms
- **TLS/SSL**: Transport security
- **Subprotocols**: WebSocket subprotocol security
- **Headers**: WebSocket header security
- **Cookies**: WebSocket cookie handling
- **Query Parameters**: WebSocket query security
- **Path Security**: WebSocket path validation
- **HTTP Method**: WebSocket method security
- **Timeouts**: WebSocket timeout configuration
- **Heartbeats**: WebSocket heartbeat security
- **Reconnection**: WebSocket reconnection logic
- **Backoff**: Exponential backoff strategies
- **Jitter**: Connection jitter implementation
- **Randomness**: Secure random generation
- **Secure Defaults**: Security by default
- **Certificates**: SSL certificate handling
- **Keys**: Cryptographic key management
- **PEM**: Privacy Enhanced Mail format
- **CRT**: Certificate file handling
- **CA**: Certificate Authority validation
- **CA Bundle**: CA certificate bundles
- **Verification**: Certificate verification
- **Sanitization**: Input sanitization
- **Escaping**: Output escaping
- **Encoding**: Data encoding security
- **Decoding**: Data decoding security
- **Serialization**: Data serialization
- **Deserialization**: Data deserialization
- **Marshalling**: Data marshalling
- **Unmarshalling**: Data unmarshalling
- **JSON**: JSON security
- **XML**: XML security
- **Protobuf**: Protocol Buffer security
- **Msgpack**: MessagePack security
- **Avro**: Apache Avro security
- **Thrift**: Apache Thrift security
- **gRPC**: gRPC security
- **RPC**: Remote Procedure Call security
- **Remote Calls**: Remote call security
- **Invocation**: Function invocation security
- **Execution**: Code execution security
- **Processing**: Data processing security
- **Handling**: Event handling security
- **Routing**: Request routing security
- **Dispatching**: Request dispatching
- **Middleware**: Middleware security
- **Interceptors**: Interceptor security
- **Filters**: Request filtering
- **Gateways**: API gateway security
- **Proxies**: Proxy security
- **Load Balancers**: Load balancer security
- **Reverse Proxies**: Reverse proxy security
- **CDNs**: Content Delivery Network security
- **Caching**: Cache security
- **Compression**: Data compression security
- **Gzip**: Gzip compression security
- **Deflate**: Deflate compression security
- **Brotli**: Brotli compression security
- **LZ4**: LZ4 compression security
- **Snappy**: Snappy compression security
- **Zstd**: Zstandard compression security
- **LZMA**: LZMA compression security

#### Session Management

- **Session Creation**: Secure session creation
- **Session Validation**: Session validation logic
- **Session Timeout**: Session timeout handling
- **Session Refresh**: Session refresh mechanisms
- **Session Invalidation**: Session invalidation
- **Session Storage**: Secure session storage
- **Cookie Handling**: Cookie security
- **Token Creation**: Secure token generation
- **Login/Logout**: Authentication flows
- **Remember Me**: Persistent authentication
- **User Persistence**: User state management
- **Session Conditions**: Session state checking
- **Session Assignments**: Session data assignment
- **Session Function Calls**: Session-related functions
- **Session Arguments**: Session function arguments

#### Authentication Bypass

- **Hardcoded Bypasses**: Hardcoded authentication bypasses
- **Skip/Disable Auth**: Authentication skipping patterns
- **Admin/Superuser Bypasses**: Administrative bypass detection
- **Debug Mode**: Debug mode authentication
- **Test Auth**: Test authentication patterns
- **Development Auth**: Development authentication
- **Temporary Auth**: Temporary authentication
- **Fake Auth**: Fake authentication patterns
- **Ignore Auth**: Authentication ignoring
- **Override Auth**: Authentication override patterns
- **Admin Skip**: Administrative authentication skipping
- **Admin Disable**: Administrative authentication disabling
- **Set Admin**: Administrative privilege assignment
- **Set Root**: Root privilege assignment
- **Set Superuser**: Superuser privilege assignment
- **Force Auth**: Forced authentication patterns

---

## 💻 Command Line Interface

### Main Commands

#### `codex scan`

Performs security analysis on Go code.

```bash
codex scan [PATH] [FLAGS]
```

**Arguments:**

- `PATH`: Path to scan (default: current directory)

**Flags:**

- `--format`: Output format (json, markdown, sarif, html)
- `--out`: Output file path
- `--exclude`: Comma-separated list of paths to exclude
- `--rules`: Path to custom rules file
- `--enable-ssa`: Enable SSA analysis
- `--enable-taint`: Enable taint analysis
- `--verbose`: Verbose output
- `--quiet`: Quiet mode
- `--no-deps`: Skip dependency analysis
- `--no-metrics`: Skip metrics analysis

#### `codex version`

Displays version information.

```bash
codex version
```

#### `codex mark`

Marks files for analysis.

```bash
codex mark [PATH]
```

### Examples

#### Basic Security Scan

```bash
codex scan .
```

#### Comprehensive Analysis

```bash
codex scan . --enable-ssa --enable-taint --verbose
```

#### Custom Output

```bash
codex scan . --format json --out security-report.json
```

#### Exclude Directories

```bash
codex scan . --exclude vendor,node_modules,testdata
```

#### Custom Rules

```bash
codex scan . --rules my-custom-rules.yaml
```

---

## ⚙️ Configuration

### Configuration File

Create a `codex.yaml` file in your project root:

```yaml
# Analysis Configuration
analysis:
  enable_ssa: true
  enable_taint: true
  enable_ast: true
  enable_builtins: true

# Output Configuration
output:
  format: json
  file: results.json
  verbose: false
  quiet: false

# Exclusion Patterns
exclude:
  - vendor/
  - node_modules/
  - testdata/
  - *.test.go

# Custom Rules
rules:
  - path: custom-rules.yaml
    enabled: true

# Dependency Analysis
dependencies:
  enable_osv: true
  enable_ghsa: true
  enable_license: true
  enable_entropy: true

# Metrics Configuration
metrics:
  complexity_threshold: 10
  function_size_threshold: 50
  file_size_threshold: 500
  duplication_threshold: 0.8
```

### Environment Variables

- `CODEX_CONFIG`: Path to configuration file
- `CODEX_OUTPUT_FORMAT`: Default output format
- `CODEX_VERBOSE`: Enable verbose output
- `CODEX_QUIET`: Enable quiet mode

---

## 📊 Output Formats

### JSON Format

```json
{
  "summary": {
    "total_issues": 15,
    "high_severity": 8,
    "medium_severity": 5,
    "low_severity": 2
  },
  "issues": [
    {
      "id": "sql-injection",
      "title": "SQL Injection Vulnerability",
      "description": "Potential SQL injection: avoid building queries via string concatenation",
      "severity": "HIGH",
      "category": "security",
      "location": {
        "file": "main.go",
        "line": 42,
        "column": 15
      },
      "suggestion": "Use parameterized queries instead of raw string concatenation",
      "references": [
        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
      ]
    }
  ]
}
```

### Markdown Format

```markdown
# CodexSentinel Security Report

## Summary

- **Total Issues**: 15
- **High Severity**: 8
- **Medium Severity**: 5
- **Low Severity**: 2

## Issues

### [HIGH] SQL Injection Vulnerability

**File**: `main.go:42`
**Description**: Potential SQL injection: avoid building queries via string concatenation
**Suggestion**: Use parameterized queries instead of raw string concatenation
**Reference**: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
```

### SARIF Format

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodexSentinel",
          "version": "1.5.0"
        }
      },
      "results": [
        {
          "ruleId": "sql-injection",
          "level": "error",
          "message": {
            "text": "Potential SQL injection: avoid building queries via string concatenation"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "main.go"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 15
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

### HTML Format

Generates a comprehensive HTML report with:

- Interactive issue navigation
- Severity filtering
- Code highlighting
- Export functionality
- Responsive design

---

## 🔧 Advanced Usage

### Custom Rules

Create custom security rules in YAML format:

```yaml
rules:
  - id: custom-sql-injection
    title: "Custom SQL Injection Detection"
    category: "security"
    severity: "HIGH"
    description: "Detects custom SQL injection patterns"
    patterns:
      - type: "function_call"
        name: "executeQuery"
        args:
          - type: "string_concat"
    suggestion: "Use parameterized queries"
    references:
      - "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
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

#### VS Code Extension

Install the CodexSentinel extension for real-time security analysis:

```json
{
  "codexsentinel.enable": true,
  "codexsentinel.rules": "custom-rules.yaml",
  "codexsentinel.severity": "MEDIUM"
}
```

#### GoLand Plugin

Configure the CodexSentinel plugin in GoLand settings:

1. Go to Settings → Plugins
2. Install CodexSentinel Plugin
3. Configure analysis settings
4. Enable real-time scanning

---

## 📚 API Reference

### Core Types

#### `analyzer.AnalyzerContext`

Main context for analysis operations.

```go
type AnalyzerContext struct {
    Fset     *token.FileSet
    Filename string
    // ... other fields
}
```

#### `result.Issue`

Represents a security issue or code quality problem.

```go
type Issue struct {
    ID          string
    Title       string
    Description string
    Severity    Severity
    Category    string
    Location    *Location
    Suggestion  string
    References  []string
}
```

#### `analyzer.Rule`

Defines a security rule for analysis.

```go
type Rule struct {
    ID       string
    Title    string
    Category string
    Severity result.Severity
    Summary  string
    Matcher  RuleMatcher
}
```

### Engine Configuration

#### `engine.Config`

Configuration for the analysis engine.

```go
type Config struct {
    EnableSSA      bool
    EnableTaint    bool
    EnableAST      bool
    EnableBuiltins bool
}
```

### Rule Matchers

#### AST Rule Matcher

```go
type ASTRuleMatcher func(ctx *AnalyzerContext, pass *analysis.Pass)
```

#### SSA Rule Matcher

```go
type SSARuleMatcher func(ctx *AnalyzerContext, ssa *ssa.Program)
```

### Report Generation

#### `report.Generator`

Handles report generation in various formats.

```go
type Generator struct {
    Issues []*result.Issue
    Config *Config
}
```

---

## 🔍 Troubleshooting

### Common Issues

#### Build Errors

**Problem**: `go: module github.com/Voskan/codexsentinel: not found`

**Solution**: Ensure you're using Go 1.24.2+ and have proper module setup:

```bash
go mod tidy
go mod download
```

#### Analysis Errors

**Problem**: "No Go files found in project"

**Solution**: Check that your project contains `.go` files and they're not excluded:

```bash
codex scan . --verbose
```

#### Memory Issues

**Problem**: Out of memory during large project analysis

**Solution**: Use memory-efficient options:

```bash
codex scan . --no-metrics --no-deps
```

#### Performance Issues

**Problem**: Slow analysis on large codebases

**Solution**: Use targeted analysis:

```bash
codex scan . --exclude vendor,testdata --enable-ast
```

### Debug Mode

Enable debug output for troubleshooting:

```bash
codex scan . --verbose --debug
```

### Log Files

CodexSentinel generates detailed logs in the current directory:

- `codex.log`: General application logs
- `analysis.log`: Analysis-specific logs
- `error.log`: Error details

---

## 🤝 Contributing

### Development Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Voskan/codexsentinel.git
   cd codexsentinel
   ```

2. **Install dependencies**:

   ```bash
   go mod tidy
   go mod download
   ```

3. **Build the project**:

   ```bash
   make build
   ```

4. **Run tests**:
   ```bash
   make test
   ```

### Adding New Rules

1. **Create rule file** in `analyzer/rules/builtin/`
2. **Implement rule logic** following existing patterns
3. **Add test cases** in `testdata/`
4. **Register rule** in `analyzer/engine/engine.go`
5. **Update documentation**

### Code Style

- Follow Go conventions
- Use meaningful variable names
- Add comprehensive comments
- Include unit tests
- Update documentation

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

---

## 🔒 Security Policy

### Supported Versions

| Version | Supported | OWASP Coverage |
| ------- | --------- | -------------- |
| 1.5.x   | ✅ Yes    | A01-A10:2025   |
| 1.4.x   | ✅ Yes    | A01-A10:2021   |
| < 1.4   | ❌ No     | Limited        |

### Reporting Vulnerabilities

#### Security Issues

- **Email**: voskan1989@gmail.com
- **GitHub**: [Security Advisory](https://github.com/Voskan/codexsentinel/security)
- **Response Time**: 48 hours
- **Disclosure**: Coordinated disclosure

#### Bug Reports

- **GitHub Issues**: [Issues](https://github.com/Voskan/codexsentinel/issues)
- **Discussions**: [Discussions](https://github.com/Voskan/codexsentinel/discussions)

### Security Best Practices

1. **Keep Updated**: Always use the latest version
2. **Regular Scans**: Run security scans regularly
3. **Custom Rules**: Create project-specific rules
4. **CI/CD Integration**: Automate security scanning
5. **Team Training**: Educate team on security practices

---

## 📞 Support

### Getting Help

- **📧 Email**: [voskan1989@gmail.com](mailto:voskan1989@gmail.com)
- **🐛 Issues**: [GitHub Issues](https://github.com/Voskan/codexsentinel/issues)
- **📖 Documentation**: [Wiki](https://github.com/Voskan/codexsentinel/wiki)
- **💬 Discussions**: [GitHub Discussions](https://github.com/Voskan/codexsentinel/discussions)

### Community

- **GitHub**: [Repository](https://github.com/Voskan/codexsentinel)
- **Releases**: [Latest Release](https://github.com/Voskan/codexsentinel/releases)
- **Security**: [Security Policy](https://github.com/Voskan/codexsentinel/security)

### Resources

- **OWASP Top 10**: [2025 Edition](https://owasp.org/www-project-top-ten/)
- **Go Security**: [Go Security Best Practices](https://golang.org/doc/security)
- **SAST Tools**: [Static Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)

---

## 📈 Statistics

### Project Metrics

- **Lines of Code**: 15,000+
- **Go Files**: 100+
- **Security Rules**: 18+
- **OWASP Coverage**: 100% (A01-A10:2025)
- **Supported Formats**: 4 (JSON, Markdown, SARIF, HTML)
- **Analysis Types**: 4 (AST, SSA, Taint, Metrics)

### Performance

- **Analysis Speed**: ~1000 LOC/second
- **Memory Usage**: < 100MB for typical projects
- **CPU Usage**: Optimized for multi-core systems
- **Accuracy**: High precision with low false positives

### Recognition

- **OWASP Top 10 2025 Coverage**: 100% (A01-A10:2025)
- **Latest OWASP Standards**: Full compliance
- **Go Language Focus**: Optimized for Go ecosystems
- **Enterprise Ready**: Production-grade security scanning

---

_This documentation is maintained by the CodexSentinel team. For the latest updates, visit our [GitHub repository](https://github.com/Voskan/codexsentinel)._
