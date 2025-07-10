// Package arch provides architectural structure analysis for Go projects.
package arch

import (
	"fmt"
	"go/token"

	"golang.org/x/tools/go/packages"
)

// ImportCycle represents a detected cycle between Go packages.
type ImportCycle struct {
	Packages []string // Ordered list of packages in the cycle
}

// AnalyzeImportCycles analyzes all packages starting from the given pattern (e.g. "./...")
// and returns detected import cycles, if any.
func AnalyzeImportCycles(pattern string) ([]ImportCycle, error) {
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedImports | packages.NeedDeps | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes,
		Dir:   ".",
		Fset:  token.NewFileSet(),
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}

	visited := make(map[string]bool)
	stack := []string{}
	var cycles []ImportCycle

	for _, pkg := range pkgs {
		detectCycle(pkg, visited, stack, make(map[string]bool), &cycles)
	}

	return cycles, nil
}

// detectCycle performs DFS traversal to detect import cycles.
func detectCycle(
	pkg *packages.Package,
	visited map[string]bool,
	stack []string,
	stackSet map[string]bool,
	cycles *[]ImportCycle,
) {
	if pkg.PkgPath == "" || visited[pkg.PkgPath] {
		return
	}

	if stackSet[pkg.PkgPath] {
		cycle := extractCycle(stack, pkg.PkgPath)
		if !containsCycle(*cycles, cycle) {
			*cycles = append(*cycles, ImportCycle{Packages: cycle})
		}
		return
	}

	stack = append(stack, pkg.PkgPath)
	stackSet[pkg.PkgPath] = true
	defer delete(stackSet, pkg.PkgPath)

	for _, imp := range pkg.Imports {
		detectCycle(imp, visited, stack, stackSet, cycles)
	}

	visited[pkg.PkgPath] = true
}

// extractCycle extracts the sequence of packages involved in the cycle.
func extractCycle(stack []string, start string) []string {
	var cycle []string
	for i := len(stack) - 1; i >= 0; i-- {
		cycle = append([]string{stack[i]}, cycle...)
		if stack[i] == start {
			break
		}
	}
	cycle = append(cycle, start)
	return cycle
}

// containsCycle checks if the same cycle already exists (order-insensitive).
func containsCycle(cycles []ImportCycle, newCycle []string) bool {
	newSet := make(map[string]struct{})
	for _, p := range newCycle {
		newSet[p] = struct{}{}
	}

	for _, c := range cycles {
		if len(c.Packages) != len(newCycle) {
			continue
		}
		match := true
		for _, p := range c.Packages {
			if _, ok := newSet[p]; !ok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// HasCycleFor reports whether a specific package is part of any cycle.
func HasCycleFor(pkg string, cycles []ImportCycle) bool {
	for _, c := range cycles {
		for _, p := range c.Packages {
			if p == pkg {
				return true
			}
		}
	}
	return false
}
