package metrics

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"github.com/Voskan/codexsentinel/v2/config"
)

// Run computes the metrics enabled in cfg over the files selected for analysis
// and reports values exceeding the configured thresholds. Dead code detection
// needs the SSA bundle and is skipped when bundle is nil. A threshold of zero
// disables the corresponding check.
func Run(ws *workspace.Workspace, bundle *codessa.GraphBundle, cfg config.MetricsConfig) []result.Issue {
	if ws == nil || !cfg.Enable {
		return nil
	}
	files, pkgOf := sourceFiles(ws)
	issues := fileMetrics(ws.Fset, files, ws.RootDir, cfg, func(file string) string { return pkgOf[file] })
	return append(issues, RunWorkspace(ws, bundle, cfg)...)
}

// RunFiles computes the metrics that depend only on the given files of one
// package: cyclomatic complexity, function size and file size. Test files are
// skipped. root is the directory file names are reported relative to in
// messages.
func RunFiles(fset *token.FileSet, files []*ast.File, pkgPath, root string, cfg config.MetricsConfig) []result.Issue {
	if !cfg.Enable {
		return nil
	}
	var selected []*ast.File
	for _, file := range files {
		name := fset.Position(file.Pos()).Filename
		if file.Pos() != token.NoPos && !strings.HasSuffix(name, "_test.go") {
			selected = append(selected, file)
		}
	}
	return fileMetrics(fset, selected, root, cfg, func(string) string { return pkgPath })
}

// RunWorkspace computes the metrics that compare packages or need the whole
// program: duplicated function bodies, mutable globals and dead code.
func RunWorkspace(ws *workspace.Workspace, bundle *codessa.GraphBundle, cfg config.MetricsConfig) []result.Issue {
	if ws == nil || !cfg.Enable {
		return nil
	}
	files, pkgOf := sourceFiles(ws)
	var issues []result.Issue
	add := adder(&issues, func(file string) string { return pkgOf[file] })
	if cfg.EnableDuplication {
		for _, block := range AnalyzeDuplicates(ws.Fset, files, cfg.MinDuplicateLOC) {
			first := block.Funcs[0]
			var others []string
			for _, fn := range block.Funcs[1:] {
				others = append(others, fmt.Sprintf("%s (%s:%d)", fn.Name, relative(ws.RootDir, fn.File), fn.Line))
			}
			add("code-duplication", "Duplicated Function Body", result.SeverityLow, first.File, first.Line, first.Name,
				fmt.Sprintf("Function %s has a %d-line body that is duplicated; also in %s.", first.Name, block.LOC, strings.Join(others, ", ")),
				"Extract the shared logic into a single function.")
		}
	}
	if cfg.EnableGlobals {
		for _, g := range AnalyzeGlobals(ws) {
			add("global-variable", "Mutable Global State", result.SeverityLow, g.File, g.Line, "",
				fmt.Sprintf("Package-level variable %s holds mutable shared state (%s).", g.Name, g.Reason),
				"Pass the state explicitly or encapsulate it in a type owned by its users.")
		}
	}
	if cfg.EnableDeadCode && bundle != nil {
		targets := map[string]bool{}
		for _, pkg := range ws.Packages {
			targets[pkg.PkgPath] = true
		}
		for _, fn := range AnalyzeDeadCodeFromGraph(bundle, targets) {
			if _, selected := pkgOf[fn.File]; !selected {
				continue
			}
			name := fn.Name
			if fn.Recv != "" {
				name = recvName(fn.Recv) + "." + name
			}
			add("dead-code", "Unused Function", result.SeverityLow, fn.File, fn.Line, name,
				fmt.Sprintf("Function %s is unreachable from any entrypoint.", name),
				"Remove the function or add the call site that should use it.")
		}
	}
	return issues
}

type addFunc func(id, title string, sev result.Severity, file string, line int, function, desc, suggestion string)

func adder(issues *[]result.Issue, pkgOf func(string) string) addFunc {
	return func(id, title string, sev result.Severity, file string, line int, function, desc, suggestion string) {
		*issues = append(*issues, result.Issue{
			ID: id, Title: title, Description: desc, Severity: sev, Confidence: 1, Category: "metrics",
			Location:   result.Location{File: file, Line: line, Column: 1, Function: function, PackagePath: pkgOf(file)},
			Suggestion: suggestion,
		})
	}
}

func fileMetrics(fset *token.FileSet, files []*ast.File, root string, cfg config.MetricsConfig, pkgOf func(string) string) []result.Issue {
	var issues []result.Issue
	add := adder(&issues, pkgOf)
	if cfg.MaxCyclomatic > 0 {
		for _, r := range AnalyzeComplexity(fset, files) {
			if r.Complexity > cfg.MaxCyclomatic {
				add("high-complexity", "High Cyclomatic Complexity", result.SeverityMedium, r.File, r.Line, r.Name,
					fmt.Sprintf("Function %s has cyclomatic complexity %d (threshold: %d).", r.Name, r.Complexity, cfg.MaxCyclomatic),
					"Split the function into smaller functions with a single responsibility.")
			}
		}
	}
	if cfg.MaxFunctionLOC > 0 {
		for _, r := range AnalyzeFunctionSizes(fset, files) {
			if r.LOC > cfg.MaxFunctionLOC {
				add("large-function", "Large Function", result.SeverityLow, r.File, r.Line, r.Name,
					fmt.Sprintf("Function %s spans %d lines (threshold: %d).", r.Name, r.LOC, cfg.MaxFunctionLOC),
					"Extract cohesive parts of the function into helpers.")
			}
		}
	}
	if cfg.MaxFileLOC > 0 {
		for _, r := range AnalyzeFileSizes(fset, files) {
			if r.LOC > cfg.MaxFileLOC {
				add("large-file", "Large File", result.SeverityLow, r.File, 1, "",
					fmt.Sprintf("File %s has %d lines (threshold: %d).", relative(root, r.File), r.LOC, cfg.MaxFileLOC),
					"Split the file into smaller files grouped by responsibility.")
			}
		}
	}
	return issues
}

// sourceFiles returns the non-test files selected for analysis, without
// duplicates, and the package path of each file.
func sourceFiles(ws *workspace.Workspace) ([]*ast.File, map[string]string) {
	var files []*ast.File
	pkgOf := map[string]string{}
	for _, pkg := range ws.Packages {
		for _, file := range ws.Files(pkg) {
			name := ws.Fset.Position(file.Pos()).Filename
			if _, dup := pkgOf[name]; dup || strings.HasSuffix(name, "_test.go") || file.Pos() == token.NoPos {
				continue
			}
			pkgOf[name] = pkg.PkgPath
			files = append(files, file)
		}
	}
	return files, pkgOf
}

func recvName(recv string) string {
	recv = strings.TrimPrefix(recv, "*")
	if i := strings.Index(recv, "["); i >= 0 {
		recv = recv[:i]
	}
	if i := strings.LastIndex(recv, "."); i >= 0 {
		recv = recv[i+1:]
	}
	return recv
}

func relative(root, file string) string {
	if root != "" {
		if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(file)
}
