// Package ssa builds a single SSA program and call graph for a loaded workspace.
package ssa

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"runtime"
	"sort"

	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// GraphBundle groups the SSA program of a workspace with its call graph.
type GraphBundle struct {
	Fset      *token.FileSet
	Program   *ssa.Program
	Packages  []*ssa.Package
	CallGraph *callgraph.Graph

	// Warnings collects non-fatal problems encountered while building SSA.
	Warnings []string
}

// BuildFromWorkspace builds SSA for the workspace (including dependencies)
// with generic instantiation and computes a VTA call graph.
func BuildFromWorkspace(ws *workspace.Workspace) (*GraphBundle, error) {
	return BuildFromWorkspaceContext(context.Background(), ws)
}

// BuildFromWorkspaceContext is BuildFromWorkspace that stops between
// packages and between the call graph phases once ctx is cancelled and then
// returns ctx.Err().
func BuildFromWorkspaceContext(ctx context.Context, ws *workspace.Workspace) (*GraphBundle, error) {
	if ws == nil {
		return nil, fmt.Errorf("nil workspace")
	}
	prog, pkgs := ssautil.AllPackages(ws.Packages, ssa.InstantiateGenerics)
	bundle := &GraphBundle{Fset: ws.Fset, Program: prog}
	for _, pkg := range pkgs {
		if pkg != nil {
			bundle.Packages = append(bundle.Packages, pkg)
		}
	}
	if err := safeBuild(ctx, prog); err != nil {
		bundle.Warnings = append(bundle.Warnings, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := bundle.buildCallGraph(ctx); err != nil {
		return nil, err
	}
	return bundle, nil
}

func safeBuild(ctx context.Context, prog *ssa.Program) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("SSA build incomplete: %v", r)
		}
	}()
	buildPackages(ctx, prog)
	return nil
}

// buildPackages builds the functions of every package of prog in parallel,
// like ssa.Program.Build, but starts no package once ctx is cancelled.
func buildPackages(ctx context.Context, prog *ssa.Program) {
	var group errgroup.Group
	group.SetLimit(runtime.GOMAXPROCS(0))
	for _, pkg := range prog.AllPackages() {
		if ctx.Err() != nil {
			break
		}
		group.Go(func() error {
			if ctx.Err() == nil {
				pkg.Build()
			}
			return nil
		})
	}
	_ = group.Wait()
}

func (g *GraphBundle) buildCallGraph(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("build call graph: %v", r)
		}
	}()
	initial := cha.CallGraph(g.Program)
	if err := ctx.Err(); err != nil {
		return err
	}
	g.CallGraph = vta.CallGraph(chaReachable(initial, g.TargetFunctions()), initial)
	return nil
}

// chaReachable returns the functions reachable from roots in the CHA call
// graph. CHA treats every function as address-taken and every type as
// converted to every interface it implements, so the set contains every
// function the analyzed code can call; VTA refines the edges between them.
// Restricting VTA to this set leaves out the many standard library and
// dependency functions the program never reaches, which would otherwise
// dominate the cost of the call graph.
func chaReachable(cg *callgraph.Graph, roots []*ssa.Function) map[*ssa.Function]bool {
	reached := make(map[*ssa.Function]bool, len(roots))
	queue := make([]*ssa.Function, 0, len(roots))
	for _, fn := range roots {
		if !reached[fn] {
			reached[fn] = true
			queue = append(queue, fn)
		}
	}
	for len(queue) > 0 {
		fn := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		node := cg.Nodes[fn]
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if callee := edge.Callee.Func; callee != nil && !reached[callee] {
				reached[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	return reached
}

// IsTarget reports whether fn belongs to one of the analyzed project packages.
func (g *GraphBundle) IsTarget(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	pkg := fn.Package()
	if pkg == nil && fn.Origin() != nil {
		pkg = fn.Origin().Package()
	}
	if pkg == nil && fn.Parent() != nil {
		return g.IsTarget(fn.Parent())
	}
	for _, target := range g.Packages {
		if target == pkg {
			return true
		}
	}
	return false
}

// TargetFunctions returns every function with a body declared in the target packages,
// including methods, closures and generic instantiations, in a deterministic order.
func (g *GraphBundle) TargetFunctions() []*ssa.Function {
	var out []*ssa.Function
	for fn := range ssautil.AllFunctions(g.Program) {
		if fn.Blocks != nil && g.IsTarget(fn) {
			out = append(out, fn)
		}
	}
	sortFuncs(out)
	return out
}

// Entrypoints returns main and init functions plus all exported functions and
// methods of the target packages.
func (g *GraphBundle) Entrypoints() []*ssa.Function {
	seen := map[*ssa.Function]bool{}
	var out []*ssa.Function
	add := func(fn *ssa.Function) {
		if fn != nil && !seen[fn] {
			seen[fn] = true
			out = append(out, fn)
		}
	}
	for _, pkg := range g.Packages {
		for name, member := range pkg.Members {
			switch m := member.(type) {
			case *ssa.Function:
				if name == "main" || name == "init" || token.IsExported(name) {
					add(m)
				}
			case *ssa.Type:
				for _, fn := range g.MethodsOf(m.Type()) {
					if token.IsExported(fn.Name()) {
						add(fn)
					}
				}
			}
		}
	}
	sortFuncs(out)
	return out
}

// MethodsOf returns the declared (non-synthetic) methods of T and *T.
func (g *GraphBundle) MethodsOf(t types.Type) []*ssa.Function {
	if named, ok := t.(*types.Named); ok && named.TypeParams().Len() > 0 {
		return nil
	}
	if _, ok := t.Underlying().(*types.Interface); ok {
		return nil
	}
	seen := map[*ssa.Function]bool{}
	var out []*ssa.Function
	for _, typ := range []types.Type{t, types.NewPointer(t)} {
		mset := g.Program.MethodSets.MethodSet(typ)
		for i := 0; i < mset.Len(); i++ {
			sel := mset.At(i)
			fn := g.Program.MethodValue(sel)
			if fn != nil && fn.Synthetic == "" && !seen[fn] {
				seen[fn] = true
				out = append(out, fn)
			}
		}
	}
	return out
}

// ReachableFrom performs a breadth-first traversal of the call graph from roots.
func (g *GraphBundle) ReachableFrom(roots []*ssa.Function) map[*ssa.Function]bool {
	reached := make(map[*ssa.Function]bool, len(roots))
	queue := make([]*ssa.Function, 0, len(roots))
	for _, root := range roots {
		if root != nil && !reached[root] {
			reached[root] = true
			queue = append(queue, root)
		}
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		var node *callgraph.Node
		if g.CallGraph != nil {
			node = g.CallGraph.Nodes[fn]
		}
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			callee := edge.Callee.Func
			if callee != nil && !reached[callee] {
				reached[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	return reached
}

// Callees returns the distinct functions fn may call according to the call graph.
func (g *GraphBundle) Callees(fn *ssa.Function) []*ssa.Function {
	if g.CallGraph == nil || g.CallGraph.Nodes[fn] == nil {
		return nil
	}
	seen := map[*ssa.Function]bool{}
	var out []*ssa.Function
	for _, edge := range g.CallGraph.Nodes[fn].Out {
		if c := edge.Callee.Func; c != nil && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sortFuncs(out)
	return out
}

// CalleesAt returns the functions a specific call site may dispatch to.
func (g *GraphBundle) CalleesAt(site ssa.CallInstruction) []*ssa.Function {
	if callee := site.Common().StaticCallee(); callee != nil {
		return []*ssa.Function{callee}
	}
	if g.CallGraph == nil {
		return nil
	}
	node := g.CallGraph.Nodes[site.Parent()]
	if node == nil {
		return nil
	}
	seen := map[*ssa.Function]bool{}
	var out []*ssa.Function
	for _, edge := range node.Out {
		if edge.Site == site && edge.Callee.Func != nil && !seen[edge.Callee.Func] {
			seen[edge.Callee.Func] = true
			out = append(out, edge.Callee.Func)
		}
	}
	sortFuncs(out)
	return out
}

// SCCs returns the strongly connected components of the call graph in reverse
// topological order: callees appear before their callers.
func (g *GraphBundle) SCCs() [][]*ssa.Function {
	if g.CallGraph == nil {
		return nil
	}
	nodes := make([]*ssa.Function, 0, len(g.CallGraph.Nodes))
	for fn := range g.CallGraph.Nodes {
		if fn != nil {
			nodes = append(nodes, fn)
		}
	}
	sortFuncs(nodes)
	t := &tarjan{g: g, index: map[*ssa.Function]int{}, low: map[*ssa.Function]int{}, onStack: map[*ssa.Function]bool{}}
	for _, fn := range nodes {
		if _, ok := t.index[fn]; !ok {
			t.visit(fn)
		}
	}
	return t.sccs
}

type tarjan struct {
	g       *GraphBundle
	next    int
	index   map[*ssa.Function]int
	low     map[*ssa.Function]int
	onStack map[*ssa.Function]bool
	stack   []*ssa.Function
	sccs    [][]*ssa.Function
}

func (t *tarjan) visit(fn *ssa.Function) {
	t.index[fn], t.low[fn] = t.next, t.next
	t.next++
	t.stack = append(t.stack, fn)
	t.onStack[fn] = true
	for _, callee := range t.g.Callees(fn) {
		if _, ok := t.index[callee]; !ok {
			t.visit(callee)
			t.low[fn] = min(t.low[fn], t.low[callee])
		} else if t.onStack[callee] {
			t.low[fn] = min(t.low[fn], t.index[callee])
		}
	}
	if t.low[fn] != t.index[fn] {
		return
	}
	var scc []*ssa.Function
	for {
		top := t.stack[len(t.stack)-1]
		t.stack = t.stack[:len(t.stack)-1]
		t.onStack[top] = false
		scc = append(scc, top)
		if top == fn {
			break
		}
	}
	sortFuncs(scc)
	t.sccs = append(t.sccs, scc)
}

// EffectiveArgs separates the receiver of a method call from its positional arguments.
// For static method calls the receiver is Args[0]; for interface invocations it is Value.
func EffectiveArgs(common *ssa.CallCommon) (recv ssa.Value, args []ssa.Value) {
	if common == nil {
		return nil, nil
	}
	if common.IsInvoke() {
		return common.Value, common.Args
	}
	if callee := common.StaticCallee(); callee != nil {
		if callee.Signature.Recv() != nil && len(common.Args) > 0 {
			return common.Args[0], common.Args[1:]
		}
		return nil, common.Args
	}
	return nil, common.Args
}

// sortFuncs orders functions by name and position. The names are computed
// once: Function.String formats the full signature path and is too costly to
// call in every comparison of a large call graph.
func sortFuncs(fns []*ssa.Function) {
	type keyed struct {
		name string
		pos  token.Pos
		fn   *ssa.Function
	}
	keys := make([]keyed, len(fns))
	for i, fn := range fns {
		keys[i] = keyed{fn.String(), fn.Pos(), fn}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].pos < keys[j].pos
	})
	for i, k := range keys {
		fns[i] = k.fn
	}
}
