# CodexSentinel API Reference

## 📚 Core API Components

### Engine Package

#### `engine.Engine`

Main analysis engine that coordinates all analysis types.

```go
type Engine struct {
    cfg *Config
}

func New(cfg *Config) *Engine
func (e *Engine) Run(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error)
```

#### `engine.Config`

Configuration for the analysis engine.

```go
type Config struct {
    EnableSSA      bool // Enables SSA-based analyzers
    EnableTaint    bool // Enables taint analysis
    EnableAST      bool // Enables AST-based rules
    EnableBuiltins bool // Enables built-in rule handlers
}
```

### Analyzer Package

#### `analyzer.AnalyzerContext`

Main context for analysis operations.

```go
type AnalyzerContext struct {
    Fset     *token.FileSet
    Filename string
    // ... other fields
}

func (ctx *AnalyzerContext) RegisterRule(rule *Rule)
func (ctx *AnalyzerContext) Report(issue result.Issue)
func (ctx *AnalyzerContext) GetFset() *token.FileSet
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

type RuleMatcher func(ctx *AnalyzerContext, pass *analysis.Pass)
```

### Result Package

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

type Severity string

const (
    SeverityHigh   Severity = "HIGH"
    SeverityMedium Severity = "MEDIUM"
    SeverityLow    Severity = "LOW"
)
```

#### `result.Location`

Represents the location of an issue in source code.

```go
type Location struct {
    File   string
    Line   int
    Column int
    Pos    token.Pos
}

func NewLocationFromPos(pos token.Pos, file, content string) *Location
```

### AST Package

#### `ast.Parser`

Handles Go source code parsing into AST.

```go
type Parser struct {
    fset *token.FileSet
}

func NewParser() *Parser
func (p *Parser) ParseFile(filename string) (*ast.File, error)
func (p *Parser) ParseDir(dir string) (map[string]*ast.File, error)
```

#### `ast.Walker`

Traverses AST nodes for analysis.

```go
type Walker struct {
    visitor ast.Visitor
}

func NewWalker(visitor ast.Visitor) *Walker
func (w *Walker) Walk(node ast.Node)
```

### SSA Package

#### `ssa.Builder`

Builds SSA form from AST.

```go
type Builder struct {
    program *ssa.Program
}

func NewBuilder() *Builder
func (b *Builder) Build(files []*ast.File) (*ssa.Program, error)
```

#### `ssa.CallGraph`

Analyzes function call relationships.

```go
type CallGraph struct {
    graph *callgraph.Graph
}

func NewCallGraph(program *ssa.Program) *CallGraph
func (cg *CallGraph) Analyze() *callgraph.Graph
```

### Flow Package

#### `flow.TaintAnalyzer`

Performs taint analysis to track untrusted data.

```go
type TaintAnalyzer struct {
    sources []Source
    sinks   []Sink
}

type Source struct {
    Name string
    Type string
}

type Sink struct {
    Name string
    Type string
}

func NewTaintAnalyzer() *TaintAnalyzer
func (ta *TaintAnalyzer) AddSource(source Source)
func (ta *TaintAnalyzer) AddSink(sink Sink)
func (ta *TaintAnalyzer) Analyze(program *ssa.Program) []*result.Issue
```

## 🔧 Rule Development API

### Creating Custom Rules

#### Basic Rule Structure

```go
func RegisterCustomRule(ctx *analyzer.AnalyzerContext) {
    ctx.RegisterRule(&analyzer.Rule{
        ID:       "custom-rule",
        Title:    "Custom Security Rule",
        Category: "security",
        Severity: result.SeverityHigh,
        Summary:  "Detects custom security patterns",
        Matcher:  matchCustomRule,
    })
}

func matchCustomRule(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
    for _, file := range pass.Files {
        ast.Inspect(file, func(n ast.Node) bool {
            // Rule logic here
            return true
        })
    }
}
```

#### AST Node Analysis

```go
func analyzeASTNode(ctx *analyzer.AnalyzerContext, node ast.Node) {
    switch n := node.(type) {
    case *ast.CallExpr:
        analyzeFunctionCall(ctx, n)
    case *ast.AssignStmt:
        analyzeAssignment(ctx, n)
    case *ast.IfStmt:
        analyzeCondition(ctx, n)
    case *ast.FuncDecl:
        analyzeFunction(ctx, n)
    }
}
```

#### Function Call Analysis

```go
func analyzeFunctionCall(ctx *analyzer.AnalyzerContext, call *ast.CallExpr) {
    if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
        if ident, ok := fun.X.(*ast.Ident); ok {
            // Analyze method calls
            analyzeMethodCall(ctx, ident.Name, fun.Sel.Name, call.Args)
        }
    } else if ident, ok := call.Fun.(*ast.Ident); ok {
        // Analyze function calls
        analyzeFunctionCall(ctx, ident.Name, call.Args)
    }
}
```

#### String Analysis

```go
func analyzeString(ctx *analyzer.AnalyzerContext, expr ast.Expr) string {
    switch e := expr.(type) {
    case *ast.BasicLit:
        if e.Kind == token.STRING {
            return e.Value
        }
    case *ast.BinaryExpr:
        if e.Op == token.ADD {
            return analyzeString(ctx, e.X) + analyzeString(ctx, e.Y)
        }
    }
    return ""
}
```

### Rule Helper Functions

#### Node String Extraction

```go
func getNodeString(ctx *analyzer.AnalyzerContext, node ast.Node) string {
    pos := ctx.GetFset().Position(node.Pos())
    return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}
```

#### Issue Reporting

```go
func reportIssue(ctx *analyzer.AnalyzerContext, id, title, description string, severity result.Severity, pos token.Pos) {
    location := result.NewLocationFromPos(pos, "", "")
    ctx.Report(result.Issue{
        ID:          id,
        Title:       title,
        Description: description,
        Severity:    severity,
        Location:    location,
        Category:    "security",
    })
}
```

## 📊 Metrics API

### Complexity Analysis

```go
func AnalyzeComplexity(ctx *analyzer.AnalyzerContext) []*result.Issue {
    var issues []*result.Issue

    for _, file := range ctx.Files {
        ast.Inspect(file, func(n ast.Node) bool {
            if funcDecl, ok := n.(*ast.FuncDecl); ok {
                complexity := calculateComplexity(funcDecl)
                if complexity > 10 {
                    issues = append(issues, &result.Issue{
                        ID:          "high-complexity",
                        Title:       "High Cyclomatic Complexity",
                        Description: fmt.Sprintf("Function has complexity %d (threshold: 10)", complexity),
                        Severity:    result.SeverityMedium,
                        Location:    result.NewLocationFromPos(funcDecl.Pos(), "", ""),
                    })
                }
            }
            return true
        })
    }

    return issues
}
```

### Duplication Detection

```go
func AnalyzeDuplication(ctx *analyzer.AnalyzerContext) []*result.Issue {
    var issues []*result.Issue

    // Implementation for code duplication detection
    // Uses AST comparison and similarity analysis

    return issues
}
```

### Size Analysis

```go
func AnalyzeSize(ctx *analyzer.AnalyzerContext) []*result.Issue {
    var issues []*result.Issue

    for _, file := range ctx.Files {
        // Analyze file size
        if fileSize := calculateFileSize(file); fileSize > 500 {
            issues = append(issues, &result.Issue{
                ID:          "large-file",
                Title:       "Large File Detected",
                Description: fmt.Sprintf("File has %d lines (threshold: 500)", fileSize),
                Severity:    result.SeverityLow,
                Location:    result.NewLocationFromPos(file.Pos(), "", ""),
            })
        }

        // Analyze function size
        ast.Inspect(file, func(n ast.Node) bool {
            if funcDecl, ok := n.(*ast.FuncDecl); ok {
                if funcSize := calculateFunctionSize(funcDecl); funcSize > 50 {
                    issues = append(issues, &result.Issue{
                        ID:          "large-function",
                        Title:       "Large Function Detected",
                        Description: fmt.Sprintf("Function has %d lines (threshold: 50)", funcSize),
                        Severity:    result.SeverityLow,
                        Location:    result.NewLocationFromPos(funcDecl.Pos(), "", ""),
                    })
                }
            }
            return true
        })
    }

    return issues
}
```

## 📦 Dependency Analysis API

### OSV Integration

```go
func AuditVulnerabilities(goModPath string) ([]Vulnerability, error) {
    // Parse go.mod file
    mod, err := parseGoMod(goModPath)
    if err != nil {
        return nil, err
    }

    // Query OSV database
    vulnerabilities, err := queryOSV(mod.Dependencies)
    if err != nil {
        return nil, err
    }

    return vulnerabilities, nil
}
```

### License Analysis

```go
func AnalyzeLicenses(goModPath string) ([]LicenseIssue, error) {
    // Parse go.mod file
    mod, err := parseGoMod(goModPath)
    if err != nil {
        return nil, err
    }

    // Check licenses
    issues, err := checkLicenses(mod.Dependencies)
    if err != nil {
        return nil, err
    }

    return issues, nil
}
```

### Entropy Analysis

```go
func AnalyzeHighEntropyStrings(path string) ([]EntropyFinding, error) {
    var findings []EntropyFinding

    // Walk through files
    err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        // Skip directories and non-Go files
        if info.IsDir() || !strings.HasSuffix(path, ".go") {
            return nil
        }

        // Analyze file for high entropy strings
        fileFindings, err := analyzeFileEntropy(path)
        if err != nil {
            return err
        }

        findings = append(findings, fileFindings...)
        return nil
    })

    return findings, err
}
```

## 📄 Report Generation API

### Report Generator

```go
type Generator struct {
    Issues []*result.Issue
    Config *Config
}

func NewGenerator(issues []*result.Issue, config *Config) *Generator
func (g *Generator) GenerateJSON() ([]byte, error)
func (g *Generator) GenerateMarkdown() ([]byte, error)
func (g *Generator) GenerateSARIF() ([]byte, error)
func (g *Generator) GenerateHTML() ([]byte, error)
```

### Format Writers

#### JSON Writer

```go
func WriteJSONReport(issues []*result.Issue, w io.Writer) error {
    report := struct {
        Summary Summary `json:"summary"`
        Issues  []*result.Issue `json:"issues"`
    }{
        Summary: computeSummary(issues),
        Issues:  issues,
    }

    return json.NewEncoder(w).Encode(report)
}
```

#### Markdown Writer

```go
func WriteMarkdownReport(issues []*result.Issue, w io.Writer) error {
    // Generate markdown report
    template := `# CodexSentinel Security Report

## Summary
- **Total Issues**: {{.Total}}
- **High Severity**: {{.High}}
- **Medium Severity**: {{.Medium}}
- **Low Severity**: {{.Low}}

## Issues
{{range .Issues}}
### [{{.Severity}}] {{.Title}}
**File**: {{.Location.File}}:{{.Location.Line}}
**Description**: {{.Description}}
**Suggestion**: {{.Suggestion}}
{{end}}
`

    // Execute template
    tmpl, err := template.New("report").Parse(template)
    if err != nil {
        return err
    }

    return tmpl.Execute(w, struct {
        Total  int
        High   int
        Medium int
        Low    int
        Issues []*result.Issue
    }{
        Total:  len(issues),
        High:   countBySeverity(issues, result.SeverityHigh),
        Medium: countBySeverity(issues, result.SeverityMedium),
        Low:    countBySeverity(issues, result.SeverityLow),
        Issues: issues,
    })
}
```

#### SARIF Writer

```go
func WriteSARIFReport(issues []*result.Issue, w io.Writer) error {
    report := SARIFReport{
        Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        Version: "2.1.0",
        Runs: []Run{
            {
                Tool: Tool{
                    Driver: Driver{
                        Name:    "CodexSentinel",
                        Version: "1.5.0",
                    },
                },
                Results: convertToSARIFResults(issues),
            },
        },
    }

    return json.NewEncoder(w).Encode(report)
}
```

## 🔧 Configuration API

### Configuration Loading

```go
type Config struct {
    Analysis AnalysisConfig `yaml:"analysis"`
    Output   OutputConfig   `yaml:"output"`
    Exclude  []string       `yaml:"exclude"`
    Rules    []RuleConfig   `yaml:"rules"`
    Dependencies DependenciesConfig `yaml:"dependencies"`
    Metrics  MetricsConfig  `yaml:"metrics"`
}

func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var config Config
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        return nil, err
    }

    return &config, nil
}
```

### Environment Variables

```go
func LoadConfigFromEnv() *Config {
    return &Config{
        Analysis: AnalysisConfig{
            EnableSSA:      getEnvBool("CODEX_ENABLE_SSA", true),
            EnableTaint:    getEnvBool("CODEX_ENABLE_TAINT", true),
            EnableAST:      getEnvBool("CODEX_ENABLE_AST", true),
            EnableBuiltins: getEnvBool("CODEX_ENABLE_BUILTINS", true),
        },
        Output: OutputConfig{
            Format: getEnvString("CODEX_OUTPUT_FORMAT", "json"),
            File:   getEnvString("CODEX_OUTPUT_FILE", ""),
            Verbose: getEnvBool("CODEX_VERBOSE", false),
            Quiet:   getEnvBool("CODEX_QUIET", false),
        },
    }
}
```

## 🧪 Testing API

### Rule Testing

```go
func TestRule(rule *analyzer.Rule, testFile string) ([]*result.Issue, error) {
    // Parse test file
    fset := token.NewFileSet()
    file, err := parser.ParseFile(fset, testFile, nil, parser.ParseComments)
    if err != nil {
        return nil, err
    }

    // Create analyzer context
    ctx := &analyzer.AnalyzerContext{
        Fset: fset,
        Files: []*ast.File{file},
    }

    // Register and run rule
    ctx.RegisterRule(rule)
    rule.Matcher(ctx, &analysis.Pass{
        Files: []*ast.File{file},
        Fset:  fset,
    })

    return ctx.GetIssues(), nil
}
```

### Benchmark Testing

```go
func BenchmarkAnalysis(b *testing.B, path string) {
    config := &engine.Config{
        EnableSSA:   true,
        EnableTaint: true,
        EnableAST:   true,
    }

    engine := engine.New(config)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ctx := &analyzer.AnalyzerContext{
            Filename: path,
        }
        _, err := engine.Run(context.Background(), ctx)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

---

_This API reference covers the core functionality of CodexSentinel. For more detailed examples and advanced usage, refer to the main documentation._
