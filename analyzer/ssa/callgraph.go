package ssa

import (
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	ssabuilder "golang.org/x/tools/go/ssa"
)

// CallGraphAnalyzer builds and inspects the call graph of a Go program.
type CallGraphAnalyzer struct {
	Fset     *token.FileSet
	Program  *ssabuilder.Program
	Graph    *callgraph.Graph
	Packages []*ssabuilder.Package
}

// NewCallGraphAnalyzer creates a new call graph analyzer from the provided source paths.
func NewCallGraphAnalyzer(paths []string) (*CallGraphAnalyzer, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports | packages.NeedFiles,
		Dir:   ".",
		Fset:  token.NewFileSet(),
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, paths...)
	if err != nil {
		return nil, err
	}

	ssaProg := ssabuilder.NewProgram(cfg.Fset, ssabuilder.SanityCheckFunctions)

	// Create SSA packages from the loaded packages
	var ssaPkgs []*ssabuilder.Package
	for _, pkg := range pkgs {
		ssaPkg := ssaProg.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
		ssaPkgs = append(ssaPkgs, ssaPkg)
	}

	ssaProg.Build()

	graph := cha.CallGraph(ssaProg)
	// Remove synthetic nodes manually since DeleteSyntheticNodes doesn't exist
	for fn := range graph.Nodes {
		if fn != nil && fn.Synthetic != "" {
			delete(graph.Nodes, fn)
		}
	}

	return &CallGraphAnalyzer{
		Fset:     cfg.Fset,
		Program:  ssaProg,
		Graph:    graph,
		Packages: ssaPkgs,
	}, nil
}

// GetCallers returns all functions that call the given function.
func (cga *CallGraphAnalyzer) GetCallers(fn *ssabuilder.Function) []*ssabuilder.Function {
	var callers []*ssabuilder.Function
	for _, edge := range cga.Graph.Nodes[fn].In {
		if edge.Caller.Func != nil {
			callers = append(callers, edge.Caller.Func)
		}
	}
	return callers
}

// GetCallees returns all functions that are called by the given function.
func (cga *CallGraphAnalyzer) GetCallees(fn *ssabuilder.Function) []*ssabuilder.Function {
	var callees []*ssabuilder.Function
	for _, edge := range cga.Graph.Nodes[fn].Out {
		if edge.Callee.Func != nil {
			callees = append(callees, edge.Callee.Func)
		}
	}
	return callees
}

// AllFunctions returns all reachable functions in the call graph.
func (cga *CallGraphAnalyzer) AllFunctions() []*ssabuilder.Function {
	var funcs []*ssabuilder.Function
	for fn := range cga.Graph.Nodes {
		if fn != nil && fn.Name() != "" {
			funcs = append(funcs, fn)
		}
	}
	return funcs
}
