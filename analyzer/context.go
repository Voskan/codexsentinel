package analyzer

import (
	"go/token"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/ssa"
)

// AnalyzerContext represents the shared context used during all analysis phases.
type AnalyzerContext struct {
	// Fset holds the parsed file set for position information.
	Fset *token.FileSet

	// Types contains type-checker results.
	Types *types.Info

	// SSA contains the SSA function representation of the current package.
	SSA *ssa.Package

	// Filename represents the absolute or relative path of the file being analyzed.
	Filename string

	// PackageName is the Go package name.
	PackageName string

	// Source holds the entire source code of the file (optional, useful for highlighting).
	Source []byte

	// CustomData is a generic key-value map that allows analyzers to store state.
	CustomData map[string]any

	// Rules stores registered rules for analysis
	Rules []*Rule

	// Issues stores found issues during analysis
	Issues []result.Issue
}

// NewAnalyzerContext creates a new AnalyzerContext instance.
func NewAnalyzerContext(
	fset *token.FileSet,
	typesInfo *types.Info,
	ssaPkg *ssa.Package,
	filename string,
	packageName string,
	source []byte,
) *AnalyzerContext {
	return &AnalyzerContext{
		Fset:        fset,
		Types:       typesInfo,
		SSA:         ssaPkg,
		Filename:    filename,
		PackageName: packageName,
		Source:      source,
		CustomData:  make(map[string]any),
		Rules:       make([]*Rule, 0),
		Issues:      make([]result.Issue, 0),
	}
}

// GetCustom retrieves a value from the CustomData map.
func (ctx *AnalyzerContext) GetCustom(key string) (any, bool) {
	v, ok := ctx.CustomData[key]
	return v, ok
}

// SetCustom sets a value in the CustomData map.
func (ctx *AnalyzerContext) SetCustom(key string, value any) {
	ctx.CustomData[key] = value
}

// RegisterRule registers a rule with the analyzer context.
func (ctx *AnalyzerContext) RegisterRule(rule *Rule) {
	ctx.Rules = append(ctx.Rules, rule)
}

// GetFset returns the file set for position information.
func (ctx *AnalyzerContext) GetFset() *token.FileSet {
	return ctx.Fset
}

// Report reports an issue found during analysis.
func (ctx *AnalyzerContext) Report(issue result.Issue) {
	ctx.Issues = append(ctx.Issues, issue)
}

// Info returns the types info.
func (ctx *AnalyzerContext) Info() *types.Info {
	return ctx.Types
}

// GetIssues returns all reported issues.
func (ctx *AnalyzerContext) GetIssues() []result.Issue {
	return ctx.Issues
}

// ClearIssues clears all reported issues.
func (ctx *AnalyzerContext) ClearIssues() {
	ctx.Issues = make([]result.Issue, 0)
}
