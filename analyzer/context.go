package analyzer

import (
	"go/token"
	"go/types"

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
