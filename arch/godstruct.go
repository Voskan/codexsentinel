// Package arch provides architectural structure analysis for Go projects.
package arch

import (
	"fmt"
	"go/token"
	"go/types"
	"path/filepath"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// GodStruct represents a struct with excessive number of methods.
type GodStruct struct {
	Name      string   // Struct name
	PkgPath   string   // Package path
	MethodNum int      // Total method count
	Methods   []string // List of method names
	Location  string   // Source file location
}

// AnalyzeGodStructs scans for structs with too many methods.
func AnalyzeGodStructs(pattern string, methodLimit int) ([]GodStruct, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedFiles,
		Dir:   ".",
		Fset:  token.NewFileSet(),
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog, _ := ssa.NewProgram(cfg.Fset, ssa.SanityCheckFunctions)
	var results []GodStruct

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		if scope == nil {
			continue
		}

		methodsByType := make(map[string][]string)
		typeFiles := make(map[string]string)

		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || !obj.Exported() {
				continue
			}

			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}

			underlying, ok := named.Underlying().(*types.Struct)
			if !ok || underlying.NumFields() == 0 {
				continue
			}

			recv := types.NewPointer(named)
			mset := types.NewMethodSet(recv)

			for i := 0; i < mset.Len(); i++ {
				sel := mset.At(i)
				fn := sel.Obj()
				if !fn.Exported() || fn.Pkg() == nil || fn.Pkg().Path() != pkg.PkgPath {
					continue
				}
				methodsByType[named.Obj().Name()] = append(methodsByType[named.Obj().Name()], fn.Name())
			}

			// Save file location
			if obj.Pos().IsValid() {
				pos := cfg.Fset.Position(obj.Pos())
				typeFiles[named.Obj().Name()] = fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line)
			}
		}

		for structName, methods := range methodsByType {
			if len(methods) > methodLimit {
				results = append(results, GodStruct{
					Name:      structName,
					PkgPath:   pkg.PkgPath,
					MethodNum: len(methods),
					Methods:   methods,
					Location:  typeFiles[structName],
				})
			}
		}
	}

	return results, nil
}
