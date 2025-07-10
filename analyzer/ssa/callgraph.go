package ssa

import (
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	ssabuilder "golang.org/x/tools/go/ssa"
)

// CallGraphAnalyzer builds and inspects the call graph of a Go program.
type CallGraphAnalyzer struct {
	Fset     *token.FileSet
	Program  *ssabuilder.Program
	Graph    *callgraph.Graph
	Packages []*ssa.Package
}

// NewCallGraphAnalyzer creates a new call graph analyzer from the provided source paths.
func NewCallGraphAnalyzer(paths []string) (*CallGraphAnalyzer, error) {
	conf := loader.Config{
		ParserMode: parserMode(),
	}
	conf.TypeChecker.Error = func(err error) {}

	for _, path := range paths {
		conf.Import(path)
	}

	prog, err := conf.Load()
	if err != nil {
		return nil, err
	}

	ssaProg := ssabuilder.NewProgram(prog.Fset, ssabuilder.SanityCheckFunctions)
	pkgs := ssabuilder.CreatePackages(prog, ssaProg, true)

	ssaProg.Build()

	graph := cha.CallGraph(ssaProg)
	callgraph.DeleteSyntheticNodes(graph)

	return &CallGraphAnalyzer{
		Fset:     prog.Fset,
		Program:  ssaProg,
		Graph:    graph,
		Packages: pkgs,
	}, nil
}

// GetCallers returns all functions that call the given function.
func (cga *CallGraphAnalyzer) GetCallers(fn *ssa.Function) []*ssa.Function {
	var callers []*ssa.Function
	for _, edge := range cga.Graph.Nodes[fn].In {
		if edge.Caller.Func != nil {
			callers = append(callers, edge.Caller.Func)
		}
	}
	return callers
}

// GetCallees returns all functions that are called by the given function.
func (cga *CallGraphAnalyzer) GetCallees(fn *ssa.Function) []*ssa.Function {
	var callees []*ssa.Function
	for _, edge := range cga.Graph.Nodes[fn].Out {
		if edge.Callee.Func != nil {
			callees = append(callees, edge.Callee.Func)
		}
	}
	return callees
}

// AllFunctions returns all reachable functions in the call graph.
func (cga *CallGraphAnalyzer) AllFunctions() []*ssa.Function {
	var funcs []*ssa.Function
	for fn := range cga.Graph.Nodes {
		if fn != nil && fn.Name() != "" {
			funcs = append(funcs, fn)
		}
	}
	return funcs
}

// parserMode returns the default parser mode for loader.Config.
func parserMode() parserModeType {
	return parserModeType(0) // use default
}

// parserModeType is a dummy alias to satisfy the interface.
type parserModeType int
