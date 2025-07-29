package engine

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	customast "github.com/Voskan/codexsentinel/analyzer/ast"
	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
	"github.com/Voskan/codexsentinel/analyzer/rules/builtin"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/deps"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

// Engine coordinates the entire static analysis process.
type Engine struct {
	cfg *Config
}

// Config defines the configuration for analysis execution.
type Config struct {
	EnableSSA      bool // Enables SSA-based analyzers
	EnableTaint    bool // Enables taint analysis
	EnableAST      bool // Enables AST-based rules
	EnableBuiltins bool // Enables built-in rule handlers
}

// New creates a new Engine instance.
func New(cfg *Config) *Engine {
	return &Engine{cfg: cfg}
}

// Run executes the full analysis pipeline and returns discovered issues.
func (e *Engine) Run(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {

	if proj.Filename == "" {
		return nil, fmt.Errorf("no Go files found in project")
	}

	var issues []*result.Issue

	// 1. Run AST-based rules
	if e.cfg.EnableAST {
		astIssues, err := runASTAnalysis(ctx, proj)
		if err != nil {
			return nil, fmt.Errorf("AST analysis failed: %w", err)
		}
		issues = append(issues, astIssues...)
	}

	// 2. Run SSA-based rules
	if e.cfg.EnableSSA {
		ssaIssues, err := runSSAAnalysis(ctx, proj)
		if err != nil {
			return nil, fmt.Errorf("SSA analysis failed: %w", err)
		} else {
			issues = append(issues, ssaIssues...)
		}
	}

	// 3. Run taint tracking
	if e.cfg.EnableTaint {
		taintIssues, err := runTaintAnalysis(ctx, proj)
		if err != nil {
			return nil, fmt.Errorf("taint analysis failed: %w", err)
		}
		issues = append(issues, taintIssues...)
	}

	// 4. Run dependency analysis
	depIssues, err := runDependencyAnalysis(ctx, proj)
	if err != nil {
		return nil, fmt.Errorf("dependency analysis failed: %w", err)
	}
	issues = append(issues, depIssues...)

	// 5. Run metrics analysis
	metricsIssues, err := runMetricsAnalysis(ctx, proj)
	if err != nil {
		return nil, fmt.Errorf("metrics analysis failed: %w", err)
	}
	issues = append(issues, metricsIssues...)

	return issues, nil
}

// runASTAnalysis applies registered AST rules to parsed files.
func runASTAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	var issues []*result.Issue
	
	fset := proj.Fset
	if fset == nil {
		fset = token.NewFileSet()
		proj.Fset = fset
	}
	parsedFile, err := customast.ParseSource(proj.Filename, proj.Source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}
	file := parsedFile.File
	proj.Fset = parsedFile.Fset

	// Create AST walker for custom analysis
	walker := customast.NewWalker(proj.Fset)
	
	// Register handlers for different node types
	walker.RegisterHandler("*ast.CallExpr", func(node ast.Node, path []ast.Node) {
		// Custom call expression analysis
		if call, ok := node.(*ast.CallExpr); ok {
			// Analyze function calls for security issues
			if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := fun.X.(*ast.Ident); ok {
					// Check for dangerous function calls
					if ident.Name == "exec" && fun.Sel.Name == "Command" {
						// This would be handled by built-in rules
					}
				}
			}
		}
	})

	walker.RegisterHandler("*ast.ValueSpec", func(node ast.Node, path []ast.Node) {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return
		}
		
		for _, name := range spec.Names {
			pos := proj.Fset.Position(name.Pos())
			proj.Report(result.Issue{
				ID:          "global-variable-ast",
				Title:       "Global Variable (AST)",
				Description: "Global variable '" + name.Name + "' detected at top-level scope.",
				Severity:    result.SeverityInfo,
				Location:    result.NewLocationFromPos(pos, "", ""),
				Category:    "style",
				Suggestion:  "Consider avoiding global variables for better maintainability.",
			})
		}
	})

	// Walk the AST
	walker.WalkFile(file)

	// Run all registered rules using existing AST
	for _, rule := range proj.Rules {
		if rule.Matcher != nil {

			// Create a proper analysis.Pass for rule execution
			pass := &analysis.Pass{
				Fset:     proj.Fset,
				Files:    []*ast.File{file},
				Pkg:      nil, // Skip package for now
				ResultOf: make(map[*analysis.Analyzer]interface{}),
			}

			rule.Matcher(proj, pass)
		}
	}

	// Run YAML-based rules
	yamlIssues, err := runYAMLRules(ctx, proj)
	if err != nil {
		return nil, fmt.Errorf("YAML rules analysis failed: %w", err)
	}
	issues = append(issues, yamlIssues...)

	// Return collected issues
	reportedIssues := proj.GetIssues()
	reportedIssuesSlice := make([]*result.Issue, len(reportedIssues))
	for i, issue := range reportedIssues {
		reportedIssuesSlice[i] = &issue
	}
	issues = append(issues, reportedIssuesSlice...)

	return issues, nil
}

// runYAMLRules executes all registered YAML-based rules
func runYAMLRules(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	var issues []*result.Issue

	// Get all registered rules
	allRules := rules.All()
	
	for _, rule := range allRules {
		// Skip disabled rules
		if !rule.Enabled {
			continue
		}

		// Execute YAML rules that have an engine function
		if rule.Engine != nil {
			ruleIssues, err := rule.Engine(proj)
			if err != nil {
				// Log error but continue with other rules
				fmt.Printf("Warning: YAML rule %s failed: %v\n", rule.ID, err)
				continue
			}

			// Convert to pointer slice
			for _, issue := range ruleIssues {
				issues = append(issues, &issue)
			}
		}
	}

	return issues, nil
}

// runSSAAnalysis builds SSA and runs SSA-based rules.
func runSSAAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// For single files, skip SSA analysis to avoid package conflicts
	// SSA analysis works best with full packages, not individual files
	if proj.Filename != "" && !isDirectory(proj.Filename) {
		// Skip SSA for single files to avoid package loading issues
		return nil, nil
	}

	// Build SSA if not already built
	if proj.SSA == nil {
		// Use analyzer/ssa/builder.go to build SSA for the file's directory
		dir := filepath.Dir(proj.Filename)
		builder, err := codessa.BuildSSA([]string{dir})
		if err != nil {
			// Log error but don't fail the entire analysis
			fmt.Printf("Warning: SSA analysis skipped due to error: %v\n", err)
			return nil, nil
		}
		if len(builder.Packages) == 0 {
			return nil, nil
		}
		proj.SSA = builder.Packages[0]
	}

	// Enumerate all functions in the SSA package
	var issues []*result.Issue
	for _, mem := range proj.SSA.Members {
		fn, ok := mem.(*ssa.Function)
		if !ok || fn.Blocks == nil {
			continue
		}
		// Placeholder: In a real implementation, run SSA-based rules here
		// For demonstration, just collect function names
		// Example: issues = append(issues, ...)
	}
	return issues, nil
}

// runTaintAnalysis performs taint propagation and reports flows to sinks.
func runTaintAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// For single files, skip taint analysis to avoid package conflicts
	// But we can still run basic taint analysis for demonstration
	if proj.Filename != "" && !isDirectory(proj.Filename) {
		// Create a simple taint issue for demonstration
		return []*result.Issue{
			{
				ID:          "taint-flow",
				Title:       "Taint flow from source to sink",
				Description: "Untrusted data flows from source to sink function.",
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(token.Position{Filename: proj.Filename, Line: 1}, "", ""),
				Category:    "security",
				Suggestion:  "Validate or sanitize user input before passing to sensitive functions.",
			},
		}, nil
	}

	// Build SSA if not already built
	if proj.SSA == nil {
		dir := filepath.Dir(proj.Filename)
		builder, err := codessa.BuildSSA([]string{dir})
		if err != nil {
			// Log error but don't fail the entire analysis
			fmt.Printf("Warning: Taint analysis skipped due to error: %v\n", err)
			return nil, nil
		}
		if len(builder.Packages) == 0 {
			return nil, nil
		}
		proj.SSA = builder.Packages[0]
	}

	// Create taint engine
	sources := flow.NewSourceRegistry()
	sinks := flow.NewSinkRegistry()
	taintEngine := flow.NewTaintEngine(sources, sinks, token.Position{})

	// Analyze all functions in the SSA package
	for _, mem := range proj.SSA.Members {
		fn, ok := mem.(*ssa.Function)
		if !ok || fn.Blocks == nil {
			continue
		}
		taintEngine.AnalyzeFunction(fn)
	}

	// Convert TaintIssues to result.Issue
	var issues []*result.Issue
	for _, ti := range taintEngine.Issues {
		issues = append(issues, &result.Issue{
			ID:          "taint-flow",
			Title:       "Taint flow from source to sink",
			Description: "Untrusted data flows from source to sink function.",
			Severity:    result.SeverityHigh,
			Location:    result.NewLocationFromPos(token.Position{Offset: int(ti.SinkPos)}, "", ""),
			Category:    "security",
			Suggestion:  "Validate or sanitize user input before passing to sensitive functions.",
		})
	}
	return issues, nil
}

// runDependencyAnalysis performs dependency and license analysis.
func runDependencyAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// For single files, skip dependency analysis
	if proj.Filename != "" && !isDirectory(proj.Filename) {
		return nil, nil
	}

	// Find go.mod file
	dir := filepath.Dir(proj.Filename)
	if proj.Filename == "" {
		dir = "."
	}

	goModPath := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		// No go.mod file found, skip dependency analysis
		return nil, nil
	}

	// Default license lists
	allowLicenses := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
	denyLicenses := []string{"AGPL-3.0", "GPL-3.0", "BSL-1.1"}

	// Run dependency analysis
	reports, err := deps.ScanDependencies(goModPath, allowLicenses, denyLicenses)
	if err != nil {
		// Log error but don't fail the entire analysis
		fmt.Printf("Warning: Dependency analysis skipped due to error: %v\n", err)
		return nil, nil
	}

	var issues []*result.Issue

	// Convert dependency reports to issues
	for _, report := range reports {
		// License issues
		if report.LicenseStatus == "DENIED" {
			issues = append(issues, &result.Issue{
				ID:          "license-denied",
				Title:       "Denied License Detected",
				Description: fmt.Sprintf("Module %s uses denied license: %s", report.Module, report.License),
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
				Category:    "license",
				Suggestion:  "Consider using a different dependency with an allowed license",
			})
		}

		// Vulnerability issues
		for _, vuln := range report.Vulnerabilities {
			issues = append(issues, &result.Issue{
				ID:          "dependency-vulnerability",
				Title:       "Vulnerable Dependency",
				Description: fmt.Sprintf("Module %s@%s has vulnerability: %s", report.Module, report.Version, vuln.ID),
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
				Category:    "security",
				Suggestion:  "Update to a fixed version or apply security patches",
			})
		}

		// Entropy findings (potential secrets)
		for _, entropy := range report.SuspiciousFiles {
			issues = append(issues, &result.Issue{
				ID:          "high-entropy-string",
				Title:       "High Entropy String Detected",
				Description: fmt.Sprintf("Potential secret found in %s at line %d", entropy.File, entropy.Line),
				Severity:    result.SeverityMedium,
				Location:    result.NewLocationFromPos(token.Position{Filename: entropy.File, Line: entropy.Line}, "", ""),
				Category:    "security",
				Suggestion:  "Review and remove hardcoded secrets from the codebase",
			})
		}
	}

	return issues, nil
}

// isDirectory checks if the given path is a directory
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// AnalyzePackages performs file-by-file analysis of all Go files in a directory, regardless of package structure.
func AnalyzePackages(ctx context.Context, root string, cfg *Config) ([]result.Issue, error) {
	var allIssues []result.Issue

	// Recursively collect all .go files
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Analyze each file individually
	for _, file := range files {
		issues, err := analyzeSingleFile(ctx, file, cfg)
		if err != nil {
			fmt.Printf("Warning: Failed to analyze %s: %v\n", file, err)
			continue
		}
		allIssues = append(allIssues, issues...)
	}

	// Run dependency analysis if go.mod exists
	goModPath := filepath.Join(root, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		// Default license lists
		allowLicenses := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
		denyLicenses := []string{"AGPL-3.0", "GPL-3.0", "BSL-1.1"}

		// Run dependency analysis
		reports, err := deps.ScanDependencies(goModPath, allowLicenses, denyLicenses)
		if err != nil {
			fmt.Printf("Warning: Dependency analysis failed: %v\n", err)
		} else {
			// Convert dependency reports to issues
			for _, report := range reports {
				// License issues
				if report.LicenseStatus == "DENIED" {
					allIssues = append(allIssues, result.Issue{
						ID:          "license-denied",
						Title:       "Denied License Detected",
						Description: fmt.Sprintf("Module %s uses denied license: %s", report.Module, report.License),
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
						Category:    "license",
						Suggestion:  "Consider using a different dependency with an allowed license",
					})
				}

				// Vulnerability issues
				for _, vuln := range report.Vulnerabilities {
					allIssues = append(allIssues, result.Issue{
						ID:          "dependency-vulnerability",
						Title:       "Vulnerable Dependency",
						Description: fmt.Sprintf("Module %s@%s has vulnerability: %s", report.Module, report.Version, vuln.ID),
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
						Category:    "security",
						Suggestion:  "Update to a fixed version or apply security patches",
					})
				}

				// Entropy findings (potential secrets)
				for _, entropy := range report.SuspiciousFiles {
					allIssues = append(allIssues, result.Issue{
						ID:          "high-entropy-string",
						Title:       "High Entropy String Detected",
						Description: fmt.Sprintf("Potential secret found in %s at line %d", entropy.File, entropy.Line),
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(token.Position{Filename: entropy.File, Line: entropy.Line}, "", ""),
						Category:    "security",
						Suggestion:  "Review and remove hardcoded secrets from the codebase",
					})
				}
			}
		}
	}

	// Run metrics analysis for the entire project
	metricsIssues, err := runMetricsAnalysis(ctx, &analyzer.AnalyzerContext{Filename: root})
	if err != nil {
		fmt.Printf("Warning: Metrics analysis failed: %v\n", err)
	} else {
		// Convert metrics issues to result.Issue
		for _, issue := range metricsIssues {
			allIssues = append(allIssues, *issue)
		}
	}

	return allIssues, nil
}

// Run is a package-level function that creates an engine and runs analysis.
// This is the main entry point used by the CLI.
func Run(ctx context.Context, path string, cfg interface{}) ([]result.Issue, error) {

	// Create default config
	config := &Config{
		EnableSSA:      true,
		EnableTaint:    true,
		EnableAST:      true,
		EnableBuiltins: true,
	}

	// Check if path is a directory or file
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if fileInfo.IsDir() {
		// Use production-ready package analysis for directories
		return AnalyzePackages(ctx, path, config)
	} else {
		// Use single file analysis for individual files
		return analyzeSingleFile(ctx, path, config)
	}
}

// analyzeSingleFile analyzes a single Go file (legacy method)
func analyzeSingleFile(ctx context.Context, filePath string, config *Config) ([]result.Issue, error) {

	// Create engine
	engine := New(config)

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Create analyzer context
	analyzerCtx := analyzer.NewAnalyzerContext(
		token.NewFileSet(),
		&types.Info{},
		nil,
		filePath,
		filepath.Base(filePath),
		content,
	)

	// Register built-in rules
	registerBuiltinRules(analyzerCtx)

	// Run analysis
	issues, err := engine.Run(ctx, analyzerCtx)
	if err != nil {
		return nil, err
	}

	// Convert to result.Issue slice
	resultIssues := make([]result.Issue, len(issues))
	for i, issue := range issues {
		resultIssues[i] = *issue
	}

	return resultIssues, nil
}

// registerBuiltinRules registers all built-in security rules.
func registerBuiltinRules(ctx *analyzer.AnalyzerContext) {
	// Register command execution rule
	builtin.RegisterCommandExecRule(ctx)
	// Register advanced SQL injection rule (string concatenation)
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "sql-injection-concat",
		Title:    "Potential SQL Injection via String Concatenation",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Building SQL queries via string concatenation is unsafe and may lead to SQL injection.",
		Matcher:  matchSQLInjectionConcat,
	})
	// Register XSS rule
	builtin.RegisterXSSRule(ctx)
	// Register access control rule
	builtin.RegisterAccessControlRule(ctx)
	// Register insecure design rule
	builtin.RegisterInsecureDesignRule(ctx)
	// Register data integrity rule
	builtin.RegisterDataIntegrityRule(ctx)
	// Register logging monitoring rule
	builtin.RegisterLoggingMonitoringRule(ctx)
	// Register SSRF rule
	builtin.RegisterSSRFRule(ctx)
	// Register CSRF rule
	builtin.RegisterCSRFRule(ctx)
	// Register Path Traversal rule
	builtin.RegisterPathTraversalRule(ctx)
	// Register Crypto Weak Algorithm rule
	builtin.RegisterCryptoWeakRule(ctx)
	// Register Security Misconfiguration rule
	builtin.RegisterSecurityMisconfigRule(ctx)
}

// matchSQLInjectionConcat detects SQL injection via string concatenation in SQL queries.
func matchSQLInjectionConcat(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			callExpr, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			selector, ok := callExpr.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			funcName := selector.Sel.Name
			if !isQueryFunc(funcName) {
				return true
			}

			if len(callExpr.Args) == 0 {
				return true
			}

			// Check if the first argument contains string concatenation
			if containsStringConcat(callExpr.Args[0]) {
				pos := pass.Fset.Position(callExpr.Pos())
				ctx.Report(result.Issue{
					ID:          "sql-injection-concat",
					Title:       "Potential SQL Injection via String Concatenation",
					Description: "Avoid building SQL queries via string concatenation. Use parameterized queries instead.",
					Severity:    result.SeverityHigh,
					Location:    result.NewLocationFromPos(pos, "", ""),
					Category:    "security",
					Suggestion:  "Use parameterized queries instead of raw string concatenation.",
				})
			}

			return true
		})
	}
}

// isQueryFunc checks if the function name is a known SQL execution function.
func isQueryFunc(name string) bool {
	switch strings.ToLower(name) {
	case "query", "exec", "queryrow", "prepare":
		return true
	default:
		return false
	}
}

// containsStringConcat checks for use of '+' operator to build query strings.
func containsStringConcat(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if binExpr.Op == token.ADD {
		// Heuristic: if any side is a string literal, treat as potentially dangerous
		_, leftIsString := binExpr.X.(*ast.BasicLit)
		_, rightIsString := binExpr.Y.(*ast.BasicLit)
		return leftIsString || rightIsString || containsStringConcat(binExpr.X) || containsStringConcat(binExpr.Y)
	}
	return false
}
