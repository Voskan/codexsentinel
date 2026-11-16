package engine

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"sort"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/baseline"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/internal/ignore"
)

// postProcess applies rule configuration and suppressions to the raw findings,
// removes duplicates, fingerprints the findings and orders them deterministically.
func postProcess(ws *workspace.Workspace, cfg *config.Config, issues []result.Issue) []result.Issue {
	files := workspaceFiles(ws)
	var inline *analyzer.InlineIgnores
	if cfg.Suppression.EnableInlineIgnore {
		inline = analyzer.CollectInlineIgnores(ws.Fset, files, ws.RootDir)
	}
	manager := loadIgnoreFile(ws.RootDir, cfg.Suppression.IgnoreFile)

	out := make([]result.Issue, 0, len(issues))
	for _, issue := range issues {
		if !ruleEnabled(issue.ID, cfg) {
			continue
		}
		if severity, ok := cfg.Rules.SeverityOverrides[issue.ID]; ok {
			issue.Severity = result.ParseSeverity(severity)
		}
		if issue.Confidence == 0 {
			issue.Confidence = 1
		}
		if issue.Confidence < cfg.Suppression.MinConfidence {
			continue
		}
		issue.Location.File = relativePath(ws.RootDir, issue.Location.File)
		if inline.Suppressed(issue.Location.File, issue.Location.Line, issue.ID) {
			continue
		}
		if manager != nil && manager.IsIgnored(issue.Location.File, issue.Location.Line, issue.ID) {
			continue
		}
		out = append(out, issue)
	}
	if inline != nil && cfg.Suppression.RequireIgnoreReason && ruleEnabled("ignore-missing-reason", cfg) {
		out = append(out, inline.MissingReasons()...)
	}
	out = dedupIssues(out)
	baseline.Assign(ws.RootDir, ws.Fset, files, out)
	sortIssues(out)
	return out
}

// workspaceFiles returns every file selected for analysis.
func workspaceFiles(ws *workspace.Workspace) []*ast.File {
	var files []*ast.File
	for _, pkg := range ws.Packages {
		files = append(files, ws.Files(pkg)...)
	}
	return files
}

// loadIgnoreFile loads the project ignore file, resolving relative paths
// against the project root. A missing file disables file-based suppression.
func loadIgnoreFile(root, path string) *ignore.Manager {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	manager := ignore.NewManager()
	manager.SetRoot(root)
	if err := manager.LoadFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load ignore file %s: %v\n", path, err)
		return nil
	}
	return manager
}

// dedupIssues keeps one finding per (file, line, rule). When several analyses
// report the same location, the one with the longest trace wins, then the one
// with the highest confidence.
func dedupIssues(issues []result.Issue) []result.Issue {
	type key struct {
		file string
		line int
		id   string
	}
	index := map[key]int{}
	out := issues[:0]
	for _, issue := range issues {
		k := key{issue.Location.File, issue.Location.Line, issue.ID}
		i, seen := index[k]
		if !seen {
			index[k] = len(out)
			out = append(out, issue)
			continue
		}
		prev := out[i]
		if len(issue.Trace) > len(prev.Trace) || (len(issue.Trace) == len(prev.Trace) && issue.Confidence > prev.Confidence) {
			out[i] = issue
		}
	}
	return out
}

// sortIssues orders findings by severity (highest first), then location and rule.
func sortIssues(issues []result.Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if c := a.Severity.Compare(b.Severity); c != 0 {
			return c > 0
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		return a.ID < b.ID
	})
}
