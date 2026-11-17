package arch

import (
	"fmt"
	"go/token"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"github.com/Voskan/codexsentinel/v2/config"
)

// RunAll runs the enabled architecture checks and returns their issues. The
// call graph is optional; without it layer checks use imports only.
func RunAll(ws *workspace.Workspace, bundle *codessa.GraphBundle, cfg config.ArchConfig) []result.Issue {
	if ws == nil {
		return nil
	}
	l := NewLayering(cfg)
	var issues []result.Issue
	layerSeverity := result.SeverityLow
	if l.Configured {
		layerSeverity = result.SeverityMedium
	}
	for _, v := range AnalyzeLayering(ws, bundle, l) {
		issues = append(issues, archIssue("arch-layer-violation", "Layer Dependency Violation", layerSeverity, v.Describe(),
			"Depend on the allowed layers only, for example through an interface defined in the calling layer.", v.Pos.Filename, v.Pos.Line, v.Pos.Column, v.FromPkg))
	}
	if cfg.CheckCycles {
		for _, c := range AnalyzeImportCycles(ws.Packages) {
			pos := importPos(ws, c.Packages[0], c.Packages[1])
			issues = append(issues, archIssue("arch-import-cycle", "Import Cycle", result.SeverityHigh,
				"Import cycle: "+strings.Join(c.Packages, " -> "), "Break the cycle by moving shared types into a lower-level package.", pos.Filename, pos.Line, pos.Column, c.Packages[0]))
		}
	}
	if cfg.CheckGodStructs {
		for _, g := range AnalyzeGodStructs(ws, cfg.GodStructMaxMethods, cfg.GodStructMaxFields) {
			issues = append(issues, archIssue("arch-god-struct", "Oversized Struct", result.SeverityLow,
				fmt.Sprintf("Struct %s has %d methods and %d fields.", g.Name, g.MethodNum, g.FieldNum),
				"Split the type by responsibility.", g.Pos.Filename, g.Pos.Line, g.Pos.Column, g.PkgPath))
		}
	}
	if cfg.CheckBoundaries {
		for _, b := range AnalyzeBoundaries(ws, l) {
			issues = append(issues, archIssue("arch-boundary-type-leak", "Infrastructure Type Crosses Layer Boundary", result.SeverityMedium, b.Message(),
				"Translate infrastructure types at the edge (e.g. map *http.Request to a domain struct) and keep inner layers independent of them.", b.Pos.Filename, b.Pos.Line, b.Pos.Column, b.PkgPath))
		}
	}
	return issues
}

// importPos returns the position of the import of to in package from.
func importPos(ws *workspace.Workspace, from, to string) token.Position {
	for _, pkg := range ws.Packages {
		if pkg.PkgPath != from {
			continue
		}
		for _, file := range ws.Files(pkg) {
			for _, spec := range file.Imports {
				if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == to {
					return ws.Fset.Position(spec.Pos())
				}
			}
		}
	}
	return token.Position{}
}

func archIssue(id, title string, severity result.Severity, desc, suggestion, file string, line, column int, pkg string) result.Issue {
	if line == 0 {
		line = 1
	}
	return result.Issue{
		ID: id, Title: title, Severity: severity, Category: "architecture", Description: desc, Suggestion: suggestion, Confidence: 1,
		Location: result.Location{File: file, Line: line, Column: column, PackagePath: pkg},
	}
}
