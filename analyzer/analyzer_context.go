package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sync"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/ssa"
)

// AnalyzerContext represents the shared context used during all analysis phases.
type AnalyzerContext struct {
	mu      sync.Mutex
	Cfg     *config.Config
	RootDir string
	Files   []*ast.File

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
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	v, ok := ctx.CustomData[key]
	return v, ok
}

// SetCustom sets a value in the CustomData map.
func (ctx *AnalyzerContext) SetCustom(key string, value any) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.CustomData == nil {
		ctx.CustomData = make(map[string]any)
	}
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
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if issue.Confidence == 0 {
		issue.Confidence = 1
	}
	if ctx.Cfg != nil && issue.Confidence < ctx.Cfg.Suppression.MinConfidence {
		return
	}
	if issue.Location.File == "" {
		issue.Location.File = ctx.Filename
	}
	if issue.Location.PackagePath == "" {
		issue.Location.PackagePath = ctx.PackageName
	}
	if ctx.Fset != nil && issue.Location.Function == "" {
		for _, file := range ctx.Files {
			if filepath.Clean(ctx.Fset.Position(file.Pos()).Filename) != filepath.Clean(issue.Location.File) {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				start, end := ctx.Fset.Position(fn.Pos()), ctx.Fset.Position(fn.End())
				if issue.Location.Line >= start.Line && issue.Location.Line <= end.Line {
					issue.Location.Function = fn.Name.Name
					break
				}
			}
		}
	}
	if ctx.RootDir != "" && filepath.IsAbs(issue.Location.File) {
		if rel, err := filepath.Rel(ctx.RootDir, issue.Location.File); err == nil {
			issue.Location.File = rel
		}
	}
	issue.Location.File = filepath.ToSlash(issue.Location.File)
	ctx.Issues = append(ctx.Issues, issue)
}

// Info returns the types info.
func (ctx *AnalyzerContext) Info() *types.Info {
	return ctx.Types
}

// GetIssues returns all reported issues.
func (ctx *AnalyzerContext) GetIssues() []result.Issue {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return append([]result.Issue(nil), ctx.Issues...)
}

// ClearIssues clears all reported issues.
func (ctx *AnalyzerContext) ClearIssues() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.Issues = nil
}
