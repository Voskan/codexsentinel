package arch

import (
	"sort"

	"golang.org/x/tools/go/packages"
)

// ImportCycle is a cycle of package imports, listed from its smallest package
// path and ending where it started.
type ImportCycle struct {
	Packages []string
}

// AnalyzeImportCycles finds import cycles among pkgs and their imports. Each
// strongly connected group of packages is reported once.
func AnalyzeImportCycles(pkgs []*packages.Package) []ImportCycle {
	graph := map[string][]string{}
	var visit func(*packages.Package)
	visit = func(p *packages.Package) {
		if p == nil || p.PkgPath == "" {
			return
		}
		if _, done := graph[p.PkgPath]; done {
			return
		}
		graph[p.PkgPath] = []string{}
		paths := make([]string, 0, len(p.Imports))
		for _, imp := range p.Imports {
			paths = append(paths, imp.PkgPath)
		}
		sort.Strings(paths)
		graph[p.PkgPath] = paths
		for _, imp := range p.Imports {
			visit(imp)
		}
	}
	for _, p := range pkgs {
		visit(p)
	}

	var cycles []ImportCycle
	for _, scc := range stronglyConnected(graph) {
		if len(scc) == 1 && !contains(graph[scc[0]], scc[0]) {
			continue
		}
		cycles = append(cycles, ImportCycle{Packages: cyclePath(graph, scc)})
	}
	sort.Slice(cycles, func(i, j int) bool { return cycles[i].Packages[0] < cycles[j].Packages[0] })
	return cycles
}

// stronglyConnected returns the strongly connected components of graph.
func stronglyConnected(graph map[string][]string) [][]string {
	nodes := make([]string, 0, len(graph))
	for n := range graph {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	index, low := map[string]int{}, map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]string
	next := 0
	var strong func(string)
	strong = func(v string) {
		index[v], low[v] = next, next
		next++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range graph[v] {
			if _, seen := index[w]; !seen {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sort.Strings(scc)
			out = append(out, scc)
		}
	}
	for _, n := range nodes {
		if _, seen := index[n]; !seen {
			strong(n)
		}
	}
	return out
}

// cyclePath returns a concrete cycle through the component, starting at its
// smallest package.
func cyclePath(graph map[string][]string, scc []string) []string {
	in := map[string]bool{}
	for _, n := range scc {
		in[n] = true
	}
	start := scc[0]
	prev := map[string]string{start: ""}
	queue := []string{start}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		for _, w := range graph[v] {
			if !in[w] {
				continue
			}
			if w == start {
				path := []string{start}
				for n := v; n != start; n = prev[n] {
					path = append([]string{n}, path...)
				}
				return append([]string{start}, path...)
			}
			if _, seen := prev[w]; !seen {
				prev[w] = v
				queue = append(queue, w)
			}
		}
	}
	return append(append([]string{}, scc...), start)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// HasCycleFor reports whether a specific package is part of any cycle.
func HasCycleFor(pkg string, cycles []ImportCycle) bool {
	for _, c := range cycles {
		if contains(c.Packages, pkg) {
			return true
		}
	}
	return false
}
