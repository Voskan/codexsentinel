package ssa

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	ssabuilder "golang.org/x/tools/go/ssa"
)

// SSABuilder is responsible for building SSA representation of Go packages.
type SSABuilder struct {
	Fset     *token.FileSet      // FileSet for position mapping
	Program  *ssa.Program        // SSA program
	Packages []*ssa.Package      // All loaded SSA packages
	Types    map[string]*types.Package // Mapping from import path to types.Package
}

// BuildSSA loads packages from the provided directory paths and builds their SSA representation.
func BuildSSA(dirs []string) (*SSABuilder, error) {
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Dir:   ".", // default dir
		Fset:  token.NewFileSet(),
		Env:   os.Environ(),
		Tests: false,
	}

	var patterns []string
	for _, dir := range dirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path %s: %w", dir, err)
		}
		patterns = append(patterns, abs)
	}
	cfg.Dir = patterns[0]

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("encountered errors while loading packages")
	}

	prog := ssabuilder.NewProgram(cfg.Fset, ssabuilder.SanityCheckFunctions)
	ssaPkgs := make([]*ssa.Package, 0, len(pkgs))
	typesMap := make(map[string]*types.Package)

	for _, pkg := range pkgs {
		if pkg.Types != nil && len(pkg.Syntax) > 0 {
			ssaPkg := prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
			ssaPkgs = append(ssaPkgs, ssaPkg)
			typesMap[pkg.PkgPath] = pkg.Types
		}
	}

	prog.Build()

	return &SSABuilder{
		Fset:     cfg.Fset,
		Program:  prog,
		Packages: ssaPkgs,
		Types:    typesMap,
	}, nil
}
