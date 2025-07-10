package engine

import (
	"context"
	"fmt"

	"github.com/codexsentinel/analyzer/ast"
	"github.com/codexsentinel/analyzer/context"
	"github.com/codexsentinel/analyzer/flow"
	"github.com/codexsentinel/analyzer/result"
	"github.com/codexsentinel/analyzer/rules"
	"github.com/codexsentinel/analyzer/ssa"
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
func (e *Engine) Run(ctx context.Context, proj *context.ProjectContext) ([]*result.Issue, error) {
	if len(proj.Files) == 0 {
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

	// 4. (Optional) Add other modules (e.g., callgraph metrics) here

	return issues, nil
}

// runASTAnalysis applies registered AST rules to parsed files.
func runASTAnalysis(ctx context.Context, proj *context.ProjectContext) ([]*result.Issue, error) {
	var all []*result.Issue

	for _, pf := range proj.Files {
		for _, rule := range rules.All() {
			if rule.YAML != nil && rule.Enabled {
				// Pattern-based matcher logic
				matches, err := ast.MatchRule(rule, pf)
				if err != nil {
					continue // Rule failure shouldn't block others
				}
				for _, m := range matches {
					all = append(all, &result.Issue{
						RuleID:     rule.ID,
						Severity:   rule.Severity,
						Title:      rule.Title,
						Location:   m.Location,
						Suggestion: rule.Suggestion,
						Description: rule.Description,
					})
				}
			}
		}
	}
	return all, nil
}

// runSSAAnalysis builds SSA and runs SSA-based rules.
func runSSAAnalysis(ctx context.Context, proj *context.ProjectContext) ([]*result.Issue, error) {
	pkg, err := ssa.BuildPackage(proj)
	if err != nil {
		return nil, err
	}
	return ssa.RunRules(ctx, pkg)
}

// runTaintAnalysis performs taint propagation and reports flows to sinks.
func runTaintAnalysis(ctx context.Context, proj *context.ProjectContext) ([]*result.Issue, error) {
	pkg, err := ssa.BuildPackage(proj)
	if err != nil {
		return nil, err
	}
	flows, err := flow.Analyze(pkg)
	if err != nil {
		return nil, err
	}
	return flow.ToIssues(flows), nil
}
