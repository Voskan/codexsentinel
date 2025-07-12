// Package arch provides architectural structure analysis for Go projects.
package arch

import (
	"fmt"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// DirectCallViolation represents a direct call between architecture layers.
type DirectCallViolation struct {
	FromPkg   string // e.g. "handler"
	ToPkg     string // e.g. "repo"
	FuncName  string // e.g. "HandleLogin"
	CallSite  string // file:line
	TargetSym string // called symbol
}

// AnalyzeDirectCalls detects direct layer violations such as handler → repo.
func AnalyzeDirectCalls(pattern string) ([]DirectCallViolation, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports | packages.NeedFiles,
		Dir:   ".",
		Fset:  token.NewFileSet(),
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	prog := ssa.NewProgram(cfg.Fset, ssa.SanityCheckFunctions)
	var allViolations []DirectCallViolation

	for _, pkg := range pkgs {
		ssaPkg := prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
		ssaPkg.Build()

		fromLayer := resolveLayerDirect(pkg.PkgPath)
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
					if callee == nil {
						continue
					}

					toPkg := resolveLayerDirect(callee.Pkg.Pkg.Path())
					if toPkg == "" || toPkg == fromLayer {
						continue
					}

					// Allowed: handler → service, service → repo
					if !isAllowedCall(fromLayer, toPkg) {
						pos := cfg.Fset.Position(instr.Pos())
						allViolations = append(allViolations, DirectCallViolation{
							FromPkg:   fromLayer,
							ToPkg:     toPkg,
							FuncName:  fn.Name(),
							CallSite:  fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line),
							TargetSym: callee.String(),
						})
					}
				}
			}
		}
	}

	return allViolations, nil
}

// resolveLayerDirect maps a package path to a logical architecture layer.
func resolveLayerDirect(pkgPath string) string {
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

// isAllowedCall returns whether a call from source → target layer is valid.
func isAllowedCall(from, to string) bool {
	valid := map[string][]string{
		"handler":   {"service", "usecase"},
		"controller": {"service"},
		"service":   {"repo", "db", "infra"},
		"usecase":   {"repo", "db"},
	}

	allowed, ok := valid[from]
	if !ok {
		return false
	}
	for _, layer := range allowed {
		if to == layer {
			return true
		}
	}
	return false
}
