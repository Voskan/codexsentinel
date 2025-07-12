package engine

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
		}
		issues = append(issues, ssaIssues...)
	}

	// 3. Run taint tracking
	if e.cfg.EnableTaint {
		taintIssues, err := runTaintAnalysis(ctx, proj)
		if err != nil {
			return nil, fmt.Errorf("taint analysis failed: %w", err)
		}
		issues = append(issues, taintIssues...)
	}

	return issues, nil
}

// runASTAnalysis applies registered AST rules to parsed files.
func runASTAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// Parse the Go file
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, proj.Filename, proj.Source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	// Type check the file
	typesInfo := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes:     make(map[ast.Node]*types.Scope),
	}

	conf := types.Config{}
	pkg, err := conf.Check(proj.PackageName, fset, []*ast.File{file}, typesInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to type check: %w", err)
	}

	// Update context with parsed data
	proj.Fset = fset
	proj.Types = typesInfo
	proj.SSA = nil // Will be built if needed

	// Run all registered rules
	for _, rule := range proj.Rules {
		if rule.Matcher != nil {
			// Create a mock analysis.Pass for rule execution
			pass := &analysis.Pass{
				Fset:   fset,
				Files:  []*ast.File{file},
				Pkg:    pkg,
				ResultOf: make(map[*analysis.Analyzer]interface{}),
			}
			
			rule.Matcher(proj, pass)
		}
	}

	// Return collected issues
	reportedIssues := proj.GetIssues()
	issues := make([]*result.Issue, len(reportedIssues))
	for i, issue := range reportedIssues {
		issues[i] = &issue
	}

	return issues, nil
}

// runSSAAnalysis builds SSA and runs SSA-based rules.
func runSSAAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// Build SSA if not already built
	if proj.SSA == nil {
		ssaPkg, err := buildSSA(proj)
		if err != nil {
			return nil, err
		}
		proj.SSA = ssaPkg
	}

	// TODO: Implement SSA-based rule execution
	return []*result.Issue{}, nil
}

// runTaintAnalysis performs taint propagation and reports flows to sinks.
func runTaintAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	// Build SSA if not already built
	if proj.SSA == nil {
		ssaPkg, err := buildSSA(proj)
		if err != nil {
			return nil, err
		}
		proj.SSA = ssaPkg
	}

	// TODO: Implement taint analysis
	return []*result.Issue{}, nil
}

// buildSSA builds the SSA representation of the package.
func buildSSA(proj *analyzer.AnalyzerContext) (*ssa.Package, error) {
	// Parse the file
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, proj.Filename, proj.Source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	// Type check
	conf := types.Config{}
	pkg, err := conf.Check(proj.PackageName, fset, []*ast.File{file}, proj.Types)
	if err != nil {
		return nil, fmt.Errorf("failed to type check: %w", err)
	}

	// Build SSA
	ssaPkg, _, err := ssautil.BuildPackage(&types.Config{}, fset, pkg, []*ast.File{file}, ssa.SanityCheckFunctions)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA: %w", err)
	}

	return ssaPkg, nil
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

	// Create engine
	engine := New(config)

	// Read file content
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Create analyzer context
	analyzerCtx := analyzer.NewAnalyzerContext(
		token.NewFileSet(),
		&types.Info{},
		nil,
		path,
		filepath.Base(path),
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
	registerCommandExecRule(ctx)
}

// registerCommandExecRule registers the command injection detection rule.
func registerCommandExecRule(ctx *analyzer.AnalyzerContext) {
	// This will be called from the builtin package
	// For now, we'll create a simple rule
	rule := &analyzer.Rule{
		ID:       "command-exec-taint",
		Title:    "Potential Command Injection via exec.Command",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Using user input in exec.Command without validation may lead to command injection.",
		Matcher:  nil, // Will be set by the builtin package
	}
	ctx.RegisterRule(rule)
}
