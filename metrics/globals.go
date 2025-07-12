// Package metrics provides analysis of code quality metrics such as global state usage.
package metrics

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"

	"golang.org/x/tools/go/packages"
)

// GlobalSymbol represents a global variable or constant in a package.
type GlobalSymbol struct {
	Name     string // Symbol name
	Kind     string // "var" or "const"
	PkgPath  string // Full import path of the package
	File     string // File where symbol is defined
	Line     int    // Line number
	Exported bool   // Whether the symbol is exported
	Mutable  bool   // Whether the symbol is a variable (mutable)
	HasInit  bool   // Whether the symbol has an initializer
}

// AnalyzeGlobals detects global variables and constants defined at package scope.
func AnalyzeGlobals(pattern string) ([]GlobalSymbol, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles,
		Dir:   ".",
		Fset:  token.NewFileSet(),
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	var results []GlobalSymbol

	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			_ = pkg.CompiledGoFiles[i] // fileName not used

			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || (gen.Tok != token.VAR && gen.Tok != token.CONST) {
					continue
				}

				for _, spec := range gen.Specs {
					valSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}

					for idx, name := range valSpec.Names {
						if name.Name == "_" {
							continue
						}

						obj := pkg.TypesInfo.Defs[name]
						if obj == nil {
							continue
						}

						var kind string
						if gen.Tok == token.VAR {
							kind = "var"
						} else {
							kind = "const"
						}

						pos := cfg.Fset.Position(name.Pos())
						hasInit := idx < len(valSpec.Values)

						symbol := GlobalSymbol{
							Name:     name.Name,
							Kind:     kind,
							PkgPath:  pkg.PkgPath,
							File:     filepath.ToSlash(pos.Filename),
							Line:     pos.Line,
							Exported: name.IsExported(),
							Mutable:  kind == "var",
							HasInit:  hasInit,
						}

						results = append(results, symbol)
					}
				}
			}
		}
	}

	return results, nil
}
