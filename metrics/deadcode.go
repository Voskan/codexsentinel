// Package metrics provides analysis of code quality metrics such as dead code detection.
package metrics

import (
	"context"
	"fmt"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/ssa"
)

// DeadFunction represents a function or method that is never used.
type DeadFunction struct {
	Name     string // Function name
	Pos      string // File and line number
	File     string // File containing the declaration
	Line     int    // Line of the declaration
	Recv     string // Receiver type (for methods)
	PkgPath  string // Package where the function is defined
	IsExport bool   // Whether the function is exported
}

// AnalyzeDeadCode loads the packages under pattern and reports unreachable functions.
func AnalyzeDeadCode(pattern string) ([]DeadFunction, error) {
	cfg := config.NewDefaultConfig()
	ws, err := workspace.Load(context.Background(), pattern, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}
	bundle, err := codessa.BuildFromWorkspace(ws)
	if err != nil {
		return nil, err
	}
	targets := map[string]bool{}
	for _, pkg := range ws.Packages {
		targets[pkg.PkgPath] = true
	}
	return AnalyzeDeadCodeFromGraph(bundle, targets), nil
}

// AnalyzeDeadCodeFromGraph reports declared functions of the target packages that
// are unreachable from program entrypoints. Exported API of library packages and
// exported methods (which may satisfy interfaces) are treated as live.
func AnalyzeDeadCodeFromGraph(bundle *codessa.GraphBundle, targetPkgPaths map[string]bool) []DeadFunction {
	if bundle == nil {
		return nil
	}
	var roots []*ssa.Function
	var candidates []*ssa.Function
	for _, pkg := range bundle.Packages {
		path := pkg.Pkg.Path()
		if len(targetPkgPaths) > 0 && !targetPkgPaths[path] {
			continue
		}
		isMain := pkg.Pkg.Name() == "main"
		for name, member := range pkg.Members {
			switch m := member.(type) {
			case *ssa.Function:
				if m.Synthetic != "" || m.TypeParams().Len() > 0 && m.Blocks == nil {
					continue
				}
				if name == "main" || name == "init" || (!isMain && token.IsExported(name)) || isTestEntrypoint(m) {
					roots = append(roots, m)
					continue
				}
				candidates = append(candidates, m)
			case *ssa.Type:
				for _, fn := range bundle.MethodsOf(m.Type()) {
					if token.IsExported(fn.Name()) {
						roots = append(roots, fn)
					} else {
						candidates = append(candidates, fn)
					}
				}
			}
		}
	}
	roots = append(roots, referencedFunctions(bundle)...)
	reached := bundle.ReachableFrom(roots)
	for fn := range reached {
		if fn.Origin() != nil {
			reached[fn.Origin()] = true
		}
	}
	var dead []DeadFunction
	seen := map[*ssa.Function]bool{}
	for _, fn := range candidates {
		if seen[fn] || reached[fn] || !fn.Pos().IsValid() {
			continue
		}
		seen[fn] = true
		pos := bundle.Fset.Position(fn.Pos())
		recv := ""
		if fn.Signature.Recv() != nil {
			recv = fn.Signature.Recv().Type().String()
		}
		dead = append(dead, DeadFunction{
			Name:     fn.Name(),
			Recv:     recv,
			PkgPath:  fn.Pkg.Pkg.Path(),
			IsExport: fn.Object() != nil && fn.Object().Exported(),
			File:     pos.Filename,
			Line:     pos.Line,
			Pos:      fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line),
		})
	}
	sort.Slice(dead, func(i, j int) bool {
		if dead[i].File != dead[j].File {
			return dead[i].File < dead[j].File
		}
		return dead[i].Line < dead[j].Line
	})
	return dead
}

// referencedFunctions returns functions used as values (callbacks, method values,
// struct fields), which are live even without a direct call edge.
func referencedFunctions(bundle *codessa.GraphBundle) []*ssa.Function {
	var out []*ssa.Function
	for _, fn := range bundle.TargetFunctions() {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				var operands []*ssa.Value
				if call, ok := instr.(ssa.CallInstruction); ok {
					common := call.Common()
					for i := range common.Args {
						operands = append(operands, &common.Args[i])
					}
				} else {
					operands = instr.Operands(operands)
				}
				for _, op := range operands {
					if op == nil || *op == nil {
						continue
					}
					switch v := (*op).(type) {
					case *ssa.Function:
						out = append(out, v)
					case *ssa.MakeClosure:
						if f, ok := v.Fn.(*ssa.Function); ok {
							out = append(out, f)
						}
					}
				}
			}
		}
	}
	return out
}

func isTestEntrypoint(fn *ssa.Function) bool {
	pos := fn.Prog.Fset.Position(fn.Pos())
	if !strings.HasSuffix(pos.Filename, "_test.go") {
		return false
	}
	for _, prefix := range []string{"Test", "Benchmark", "Example", "Fuzz"} {
		if strings.HasPrefix(fn.Name(), prefix) {
			return true
		}
	}
	return false
}
