// Package arch provides architectural layer enforcement analysis.
package arch

import (
	"fmt"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// LayerViolation represents a violation of architectural layer rules.
type LayerViolation struct {
	FromPkg   string // e.g. "handler"
	ToPkg     string // e.g. "repo"
	FuncName  string // e.g. "HandleLogin"
	CallSite  string // file:line
	TargetSym string // full symbol name
}

// AnalyzeLayering inspects the project for improper layer dependencies.
func AnalyzeLayering(pattern string) ([]LayerViolation, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax | packages.NeedImports | packages.NeedDeps | packages.NeedFiles,
		Fset:  token.NewFileSet(),
		Dir:   ".",
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog := ssa.NewProgram(cfg.Fset, ssa.SanityCheckFunctions)
	var violations []LayerViolation

	for _, pkg := range pkgs {
		ssaPkg := prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
		ssaPkg.Build()

		fromLayer := resolveLayer(pkg.PkgPath)
		if fromLayer == "" {
			continue
		}

		for _, mem := range ssaPkg.Members {
			fn, ok := mem.(*ssa.Function)
			if !ok || fn.Blocks == nil {
				continue
			}

			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					call, ok := instr.(ssa.CallInstruction)
					if !ok {
						continue
					}

					callee := call.Common().StaticCallee()
					if callee == nil || callee.Pkg == nil {
						continue
					}

					toPkg := callee.Pkg.Pkg.Path()
					toLayer := resolveLayer(toPkg)
					if toLayer == "" || toLayer == fromLayer {
						continue
					}

					if !isAllowedLayerCall(fromLayer, toLayer) {
						pos := cfg.Fset.Position(instr.Pos())
						violations = append(violations, LayerViolation{
							FromPkg:   fromLayer,
							ToPkg:     toLayer,
							FuncName:  fn.Name(),
							CallSite:  fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line),
							TargetSym: callee.String(),
						})
					}
				}
			}
		}
	}

	return violations, nil
}

// resolveLayer maps a package path to a logical architecture layer.
func resolveLayer(pkgPath string) string {
	switch {
	case strings.Contains(pkgPath, "/handler"):
		return "handler"
	case strings.Contains(pkgPath, "/controller"):
		return "controller"
	case strings.Contains(pkgPath, "/service"):
		return "service"
	case strings.Contains(pkgPath, "/usecase"):
		return "usecase"
	case strings.Contains(pkgPath, "/repository"):
		return "repo"
	case strings.Contains(pkgPath, "/db"):
		return "db"
	case strings.Contains(pkgPath, "/infra"):
		return "infra"
	default:
		return ""
	}
}

// isAllowedLayerCall defines permitted calls between architecture layers.
func isAllowedLayerCall(from, to string) bool {
	// Define allowed layer-to-layer access rules.
	allowed := map[string][]string{
		"handler":    {"controller", "service", "usecase"},
		"controller": {"service", "usecase"},
		"service":    {"usecase", "repo", "db", "infra"},
		"usecase":    {"repo", "db"},
		"repo":       {"db"},
	}

	if list, ok := allowed[from]; ok {
		for _, allowedTo := range list {
			if to == allowedTo {
				return true
			}
		}
	}
	return false
}
