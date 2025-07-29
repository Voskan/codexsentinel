# CodexSentinel Examples Guide

## 🚀 Getting Started Examples

### Basic Usage

#### Simple Scan

```bash
# Scan current directory
codex scan .

# Output: Found 5 security issues
# [HIGH] SQL Injection at main.go:42
# [MEDIUM] High Complexity at utils.go:15
# [LOW] Large Function at handler.go:78
```

#### Specific Directory Scan

```bash
# Scan specific project
codex scan /path/to/my/go/project

# Scan with exclusions
codex scan . --exclude vendor,node_modules,testdata
```

#### Output Formats

```bash
# JSON output
codex scan . --format json --out security-report.json

# Markdown report
codex scan . --format markdown --out report.md

# HTML report
codex scan . --format html --out report.html

# SARIF for CI/CD
codex scan . --format sarif --out results.sarif
```

### Advanced Analysis

#### Comprehensive Scan

```bash
# Enable all analysis types
codex scan . --enable-ssa --enable-taint --verbose

# Output:
# [INFO] Starting CodexSentinel analysis...
# [INFO] Running AST analysis...
# [INFO] Running SSA analysis...
# [INFO] Running taint analysis...
# [INFO] Running dependency analysis...
# [INFO] Running metrics analysis...
# [INFO] Analysis complete! Found 12 issues
```

#### Custom Rules

```bash
# Use custom rules file
codex scan . --rules my-custom-rules.yaml

# Custom rules file content:
# rules:
#   - id: custom-sql-injection
#     title: "Custom SQL Injection Detection"
#     category: "security"
#     severity: "HIGH"
#     patterns:
#       - type: "function_call"
#         name: "executeQuery"
#         args:
#           - type: "string_concat"
```

## 🔧 Configuration Examples

### Basic Configuration

#### `codex.yaml`

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

#### `.env` file

```bash
# Analysis Configuration
CODEX_ENABLE_SSA=true
CODEX_ENABLE_TAINT=true
CODEX_ENABLE_AST=true
CODEX_ENABLE_BUILTINS=true

# Output Configuration
CODEX_OUTPUT_FORMAT=json
CODEX_OUTPUT_FILE=results.json
CODEX_VERBOSE=false
CODEX_QUIET=false

# Custom Configuration
CODEX_RULES_FILE=custom-rules.yaml
CODEX_EXCLUDE_PATHS=vendor,node_modules,testdata
```

## 🛡️ Security Rule Examples

### SQL Injection Detection

#### Vulnerable Code

```go
// ❌ Vulnerable - String concatenation
func getUserByID(id string) (*User, error) {
    query := "SELECT * FROM users WHERE id = " + id
    return db.Query(query)
}

// ❌ Vulnerable - fmt.Sprintf
func getUserByName(name string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    return db.Query(query)
}
```

#### Secure Code

```go
// ✅ Secure - Parameterized query
func getUserByID(id string) (*User, error) {
    query := "SELECT * FROM users WHERE id = ?"
    return db.Query(query, id)
}

// ✅ Secure - Prepared statement
func getUserByName(name string) (*User, error) {
    stmt, err := db.Prepare("SELECT * FROM users WHERE name = ?")
    if err != nil {
        return nil, err
    }
    defer stmt.Close()
    return stmt.Query(name)
}
```

### XSS Prevention

#### Vulnerable Code

```go
// ❌ Vulnerable - Direct output
func handleUserInput(w http.ResponseWriter, input string) {
    fmt.Fprintf(w, "<div>%s</div>", input)
}

// ❌ Vulnerable - Template without escaping
func renderTemplate(w http.ResponseWriter, data map[string]interface{}) {
    tmpl := template.Must(template.New("user").Parse(`
        <div>{{.UserInput}}</div>
    `))
    tmpl.Execute(w, data)
}
```

#### Secure Code

```go
// ✅ Secure - HTML escaping
func handleUserInput(w http.ResponseWriter, input string) {
    escaped := html.EscapeString(input)
    fmt.Fprintf(w, "<div>%s</div>", escaped)
}

// ✅ Secure - Template with escaping
func renderTemplate(w http.ResponseWriter, data map[string]interface{}) {
    tmpl := template.Must(template.New("user").Parse(`
        <div>{{.UserInput | html}}</div>
    `))
    tmpl.Execute(w, data)
}
```

### Authentication Bypass Prevention

#### Vulnerable Code

```go
// ❌ Vulnerable - Hardcoded bypass
func checkAuth(user string) bool {
    if user == "admin" {
        return true // Hardcoded bypass
    }
    return validateUser(user)
}

// ❌ Vulnerable - Debug mode
func authenticate(token string) bool {
    if debugMode {
        return true // Debug bypass
    }
    return validateToken(token)
}
```

#### Secure Code

```go
// ✅ Secure - Proper validation
func checkAuth(user string) bool {
    return validateUser(user)
}

// ✅ Secure - No debug bypass
func authenticate(token string) bool {
    return validateToken(token)
}
```

### Cryptographic Security

#### Vulnerable Code

```go
// ❌ Vulnerable - Weak hash
import "crypto/md5"

func hashPassword(password string) string {
    hash := md5.Sum([]byte(password))
    return hex.EncodeToString(hash[:])
}

// ❌ Vulnerable - Weak encryption
import "crypto/des"

func encryptData(data []byte, key []byte) ([]byte, error) {
    block, err := des.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return encrypt(block, data)
}
```

#### Secure Code

```go
// ✅ Secure - Strong hash
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

// ✅ Secure - Strong encryption
import "crypto/aes"
import "crypto/cipher"

func encryptData(data []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    return gcm.Seal(nonce, nonce, data, nil), nil
}
```

## 📊 Code Quality Examples

### Complexity Management

#### High Complexity Function

```go
// ❌ High complexity (15)
func processUserData(user *User, config *Config, options *Options) error {
    if user == nil {
        return errors.New("user is nil")
    }
    if config == nil {
        return errors.New("config is nil")
    }
    if options == nil {
        return errors.New("options is nil")
    }
    if user.ID == "" {
        return errors.New("user ID is empty")
    }
    if user.Name == "" {
        return errors.New("user name is empty")
    }
    if user.Email == "" {
        return errors.New("user email is empty")
    }
    if config.Database == "" {
        return errors.New("database is empty")
    }
    if config.Host == "" {
        return errors.New("host is empty")
    }
    if config.Port == 0 {
        return errors.New("port is invalid")
    }
    if options.Timeout == 0 {
        return errors.New("timeout is invalid")
    }
    if options.RetryCount == 0 {
        return errors.New("retry count is invalid")
    }
    if options.MaxConnections == 0 {
        return errors.New("max connections is invalid")
    }
    // Process user data...
    return nil
}
```

#### Refactored Function

```go
// ✅ Low complexity (3)
func processUserData(user *User, config *Config, options *Options) error {
    if err := validateUser(user); err != nil {
        return err
    }
    if err := validateConfig(config); err != nil {
        return err
    }
    if err := validateOptions(options); err != nil {
        return err
    }
    return processData(user, config, options)
}

func validateUser(user *User) error {
    if user == nil {
        return errors.New("user is nil")
    }
    if user.ID == "" {
        return errors.New("user ID is empty")
    }
    if user.Name == "" {
        return errors.New("user name is empty")
    }
    if user.Email == "" {
        return errors.New("user email is empty")
    }
    return nil
}
```

### Function Size Management

#### Large Function

```go
// ❌ Large function (80+ lines)
func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
    // Parse request
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse JSON
    var request Request
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // Validate request
    if request.UserID == "" {
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }
    if request.Data == "" {
        http.Error(w, "Data is required", http.StatusBadRequest)
        return
    }

    // Process data
    processedData, err := processData(request.Data)
    if err != nil {
        http.Error(w, "Processing failed", http.StatusInternalServerError)
        return
    }

    // Save to database
    if err := saveToDatabase(request.UserID, processedData); err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    // Send response
    response := Response{
        Status: "success",
        Data:   processedData,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

#### Refactored Function

```go
// ✅ Small, focused functions
func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
    request, err := parseRequest(r)
    if err != nil {
        respondWithError(w, err, http.StatusBadRequest)
        return
    }

    if err := validateRequest(request); err != nil {
        respondWithError(w, err, http.StatusBadRequest)
        return
    }

    result, err := processRequest(request)
    if err != nil {
        respondWithError(w, err, http.StatusInternalServerError)
        return
    }

    respondWithSuccess(w, result)
}

func parseRequest(r *http.Request) (*Request, error) {
    if r.Method != "POST" {
        return nil, errors.New("method not allowed")
    }

    var request Request
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        return nil, errors.New("invalid JSON")
    }

    return &request, nil
}
```

## 🔄 CI/CD Integration Examples

### GitHub Actions

#### Basic Security Scan

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

#### Advanced Security Pipeline

```yaml
name: Advanced Security Pipeline
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        analysis: [basic, comprehensive, custom]

    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: "1.24"

      - name: Install CodexSentinel
        run: go install github.com/Voskan/codexsentinel/cmd/codex@latest

      - name: Basic Security Scan
        if: matrix.analysis == 'basic'
        run: codex scan . --format json --out basic-results.json

      - name: Comprehensive Security Scan
        if: matrix.analysis == 'comprehensive'
        run: codex scan . --enable-ssa --enable-taint --format json --out comprehensive-results.json

      - name: Custom Rules Scan
        if: matrix.analysis == 'custom'
        run: codex scan . --rules custom-rules.yaml --format json --out custom-results.json

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results-${{ matrix.analysis }}
          path: ${{ matrix.analysis }}-results.json
```

### GitLab CI

#### Security Pipeline

```yaml
stages:
  - security

security-scan:
  stage: security
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex@latest
    - codex scan . --format json --out results.json
  artifacts:
    reports:
      security: results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

#### Advanced GitLab Pipeline

```yaml
variables:
  CODEX_VERSION: "1.5.0"

stages:
  - security
  - quality

security-scan:
  stage: security
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex@v${CODEX_VERSION}@latest
    - codex scan . --enable-ssa --enable-taint --format json --out security-results.json
  artifacts:
    reports:
      security: security-results.json
    paths:
      - security-results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

quality-scan:
  stage: quality
  image: golang:1.24
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex@v${CODEX_VERSION}@latest
    - codex scan . --no-deps --format json --out quality-results.json
  artifacts:
    paths:
      - quality-results.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Jenkins Pipeline

#### Declarative Pipeline

```groovy
pipeline {
    agent any

    environment {
        CODEX_VERSION = '1.5.0'
    }

    stages {
        stage('Security Scan') {
            steps {
                sh 'go install github.com/Voskan/codexsentinel/cmd/codex@v${CODEX_VERSION}@latest'
                sh 'codex scan . --format json --out security-results.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json', fingerprint: true
                }
            }
        }

        stage('Quality Analysis') {
            steps {
                sh 'codex scan . --no-deps --format json --out quality-results.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'quality-results.json', fingerprint: true
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
```

## 🛠️ Custom Rules Examples

### Custom SQL Injection Rule

#### Rule Definition

```yaml
# custom-sql-rules.yaml
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
      - type: "function_call"
        name: "executeRaw"
        args:
          - type: "string_concat"
    suggestion: "Use parameterized queries instead of string concatenation"
    references:
      - "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
```

#### Usage

```bash
codex scan . --rules custom-sql-rules.yaml --format json --out custom-results.json
```

### Custom Authentication Rule

#### Rule Definition

```yaml
# custom-auth-rules.yaml
rules:
  - id: custom-auth-bypass
    title: "Custom Authentication Bypass Detection"
    category: "security"
    severity: "HIGH"
    description: "Detects custom authentication bypass patterns"
    patterns:
      - type: "function_call"
        name: "skipAuth"
      - type: "function_call"
        name: "bypassAuth"
      - type: "assignment"
        target: "debugMode"
        value: "true"
    suggestion: "Remove authentication bypass patterns"
    references:
      - "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
```

### Custom Crypto Rule

#### Rule Definition

```yaml
# custom-crypto-rules.yaml
rules:
  - id: custom-weak-crypto
    title: "Custom Weak Crypto Detection"
    category: "security"
    severity: "HIGH"
    description: "Detects custom weak cryptographic patterns"
    patterns:
      - type: "import"
        path: "crypto/md5"
      - type: "import"
        path: "crypto/sha1"
      - type: "function_call"
        name: "md5.Sum"
      - type: "function_call"
        name: "sha1.Sum"
    suggestion: "Use strong cryptographic algorithms like SHA-256 or bcrypt"
    references:
      - "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
```

## 📊 Report Examples

### JSON Report Output

```json
{
  "summary": {
    "total_issues": 15,
    "high_severity": 8,
    "medium_severity": 5,
    "low_severity": 2,
    "categories": {
      "security": 12,
      "quality": 3
    }
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
    },
    {
      "id": "high-complexity",
      "title": "High Cyclomatic Complexity",
      "description": "Function processData has complexity 15 (threshold: 10)",
      "severity": "MEDIUM",
      "category": "quality",
      "location": {
        "file": "utils.go",
        "line": 15,
        "column": 1
      },
      "suggestion": "Consider breaking down the function into smaller functions"
    }
  ]
}
```

### Markdown Report Output

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

### [MEDIUM] High Cyclomatic Complexity

**File**: `utils.go:15`
**Description**: Function processData has complexity 15 (threshold: 10)
**Suggestion**: Consider breaking down the function into smaller functions

### [HIGH] Vulnerable Dependency

**File**: `go.mod:0`
**Description**: Module github.com/go-yaml/yaml@v2.1.0+incompatible has vulnerability: GHSA-r88r-gmrh-7j83
**Suggestion**: Update to a fixed version or apply security patches
```

## 🔍 Troubleshooting Examples

### Common Issues and Solutions

#### Build Errors

```bash
# Problem: Module not found
go: module github.com/Voskan/codexsentinel: not found

# Solution: Update Go version and modules
go version  # Ensure Go 1.24+
go mod tidy
go mod download
```

#### Analysis Errors

```bash
# Problem: No Go files found
codex scan . --verbose

# Solution: Check file extensions and exclusions
find . -name "*.go"  # Verify Go files exist
codex scan . --exclude ""  # Clear exclusions
```

#### Performance Issues

```bash
# Problem: Slow analysis on large codebase
# Solution: Use targeted analysis
codex scan . --exclude vendor,testdata --enable-ast
codex scan . --no-metrics --no-deps
```

#### Memory Issues

```bash
# Problem: Out of memory
# Solution: Use memory-efficient options
codex scan . --no-metrics --no-deps --enable-ast
```

### Debug Mode

```bash
# Enable debug output
codex scan . --verbose --debug

# Check log files
cat codex.log
cat analysis.log
cat error.log
```

---

_These examples demonstrate the most common use cases for CodexSentinel. For more advanced scenarios, refer to the main documentation and API reference._
