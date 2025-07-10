// Package metrics provides analysis of code quality metrics such as dead code detection.
package metrics

import (
	"fmt"
	"go/token"
	"path/filepath"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// DeadFunction represents a function or method that is never used.
type DeadFunction struct {
	Name     string // Fully-qualified function name
	Pos      string // File and line number
	Recv     string // Receiver type (for methods)
	PkgPath  string // Package where the function is defined
	IsExport bool   // Whether the function is exported
}

// AnalyzeDeadCode analyzes all packages for unused (dead) functions.
func AnalyzeDeadCode(pattern string) ([]DeadFunction, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports | packages.NeedFiles,
		Fset:  token.NewFileSet(),
		Dir:   ".",
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, ssaPkgs := ssa.NewProgram(cfg.Fset, ssa.SanityCheckFunctions)

	// Build all SSA packages
	for _, p := range ssaPkgs {
		p.Build()
	}

	callGraph := make(map[*ssa.Function]bool)
	allFuncs := make(map[*ssa.Function]bool)

	// Collect all reachable (called) functions
	for _, p := range ssaPkgs {
		for _, m := range p.Members {
			fn, ok := m.(*ssa.Function)
			if !ok || fn.Blocks == nil {
				continue
			}
			markReachable(fn, callGraph)
		}
	}

	// Collect all defined functions
	for _, p := range ssaPkgs {
		for _, mem := range p.Members {
			fn, ok := mem.(*ssa.Function)
			if !ok || fn.Pkg == nil || fn.Blocks == nil {
				continue
			}
			allFuncs[fn] = true
		}
	}

	var deadFuncs []DeadFunction
	for fn := range allFuncs {
		// Skip synthetic/builtin/test/init/main functions
		if fn.Synthetic != "" || isEntrypoint(fn) {
			continue
		}
		if _, ok := callGraph[fn]; ok {
			continue // called → not dead
		}

		pos := cfg.Fset.Position(fn.Pos())
		recv := ""
		if fn.Signature.Recv() != nil {
			recv = fn.Signature.Recv().Type().String()
		}
		isExported := isExportedFunc(fn)

		deadFuncs = append(deadFuncs, DeadFunction{
			Name:     fn.Name(),
			Recv:     recv,
			PkgPath:  fn.Pkg.Pkg.Path(),
			IsExport: isExported,
			Pos:      fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line),
		})
	}

	return deadFuncs, nil
}

// markReachable recursively marks reachable functions from the call tree.
func markReachable(fn *ssa.Function, visited map[*ssa.Function]bool) {
	if visited[fn] {
		return
	}
	visited[fn] = true

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee != nil && callee != fn {
				markReachable(callee, visited)
			}
		}
	}
}

// isExportedFunc determines if a function is exported.
func isExportedFunc(fn *ssa.Function) bool {
	return fn.Object() != nil && fn.Object().Exported()
}

// isEntrypoint determines if the function is considered an entrypoint.
func isEntrypoint(fn *ssa.Function) bool {
	return fn.Name() == "main" || fn.Name() == "init"
}
