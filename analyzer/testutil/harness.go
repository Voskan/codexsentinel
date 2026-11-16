// Package testutil provides a declarative harness for testing analysis rules
// against in-memory Go modules annotated with `// want "rule-id"` comments.
package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// DefaultModule is the module path used when the fixture does not provide go.mod.
const DefaultModule = "example.com/fixture"

// Expectation is one `// want` entry: an issue ID and an optional message substring.
type Expectation struct {
	File    string
	Line    int
	RuleID  string
	Message string
}

// Fixture is a materialized in-memory module.
type Fixture struct {
	Dir       string
	Workspace *workspace.Workspace
	Config    *config.Config
}

// WriteModule writes files into a fresh temporary directory, adding go.mod if missing.
func WriteModule(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files = cloneFiles(files)
		files["go.mod"] = "module " + DefaultModule + "\n\ngo 1.24\n"
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

func cloneFiles(files map[string]string) map[string]string {
	out := make(map[string]string, len(files)+1)
	for k, v := range files {
		out[k] = v
	}
	return out
}

// LoadFixture writes files to a temporary module and loads it as a workspace.
func LoadFixture(t testing.TB, files map[string]string, cfg *config.Config) *Fixture {
	t.Helper()
	dir := WriteModule(t, files)
	if cfg == nil {
		defaults := config.NewDefaultConfig()
		cfg = &defaults
	}
	ws, err := workspace.Load(context.Background(), dir, cfg)
	if err != nil {
		t.Fatalf("load fixture workspace: %v", err)
	}
	return &Fixture{Dir: dir, Workspace: ws, Config: cfg}
}

// AnalyzeFixture runs the rules registered by registerFn on every package of the fixture.
func AnalyzeFixture(t testing.TB, fx *Fixture, registerFn func(*analyzer.AnalyzerContext)) []result.Issue {
	t.Helper()
	var issues []result.Issue
	for _, pkg := range fx.Workspace.Packages {
		issues = append(issues, analyzePackage(fx, pkg, registerFn)...)
	}
	sortIssues(issues)
	return issues
}

func analyzePackage(fx *Fixture, pkg *packages.Package, registerFn func(*analyzer.AnalyzerContext)) []result.Issue {
	ws := fx.Workspace
	ac := analyzer.NewAnalyzerContext(ws.Fset, pkg.TypesInfo, nil, "", pkg.PkgPath, nil)
	ac.Cfg, ac.RootDir = fx.Config, ws.RootDir
	pass := workspace.NewAnalysisPass(ws, pkg, func(d analysis.Diagnostic) {
		ac.Report(result.Issue{ID: d.Category, Description: d.Message, Severity: result.SeverityMedium, Location: result.NewLocationFromPos(ws.Fset.Position(d.Pos), "", pkg.PkgPath)})
	})
	if len(pass.Files) == 0 {
		return nil
	}
	ac.Files = pass.Files
	ac.Filename = ws.Fset.Position(pass.Files[0].Pos()).Filename
	if registerFn != nil {
		registerFn(ac)
	}
	for _, rule := range ac.Rules {
		if rule.Matcher != nil {
			rule.Matcher(ac, pass)
		}
	}
	return ac.GetIssues()
}

// RunRulesOnFiles builds a temporary module from files, runs the rules registered by
// registerFn and checks every `// want` annotation. Unexpected and missing issues fail t.
func RunRulesOnFiles(t testing.TB, files map[string]string, registerFn func(*analyzer.AnalyzerContext)) []result.Issue {
	t.Helper()
	fx := LoadFixture(t, files, nil)
	issues := AnalyzeFixture(t, fx, registerFn)
	CheckExpectations(t, files, issues)
	return issues
}

// CheckExpectations compares issues with the `// want` annotations found in files.
func CheckExpectations(t testing.TB, files map[string]string, issues []result.Issue) {
	t.Helper()
	wants, err := ParseExpectations(files)
	if err != nil {
		t.Fatalf("parse expectations: %v", err)
	}
	for _, problem := range DiffExpectations(wants, issues) {
		t.Errorf("%s", problem)
	}
}

var (
	wantComment = regexp.MustCompile(`//\s*want\s+(.*)$`)
	wantString  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|` + "`[^`]*`")
)

// ParseExpectations extracts `// want "id"` and `// want "id:message"` annotations
// from the .go files of a fixture.
func ParseExpectations(files map[string]string) ([]Expectation, error) {
	var out []Expectation
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		for i, line := range strings.Split(files[name], "\n") {
			m := wantComment.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			literals := wantString.FindAllString(m[1], -1)
			if len(literals) == 0 {
				return nil, fmt.Errorf("%s:%d: malformed want annotation", name, i+1)
			}
			for _, lit := range literals {
				value, err := strconv.Unquote(lit)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %v", name, i+1, err)
				}
				id, msg, _ := strings.Cut(value, ":")
				out = append(out, Expectation{File: filepath.ToSlash(name), Line: i + 1, RuleID: id, Message: msg})
			}
		}
	}
	return out, nil
}

// DiffExpectations returns human-readable problems for missing and unexpected issues.
// Issue files may be absolute or relative; they are matched by path suffix.
func DiffExpectations(wants []Expectation, issues []result.Issue) []string {
	used := make([]bool, len(issues))
	var problems []string
	for _, want := range wants {
		found := false
		for i, issue := range issues {
			if used[i] || issue.ID != want.RuleID || issue.Location.Line != want.Line || !sameFile(issue.Location.File, want.File) {
				continue
			}
			if want.Message != "" && !strings.Contains(issue.Title+" "+issue.Description+" "+issue.Suggestion, want.Message) {
				continue
			}
			used[i], found = true, true
			break
		}
		if !found {
			problems = append(problems, fmt.Sprintf("missing expected issue %s at %s:%d", want.RuleID, want.File, want.Line))
		}
	}
	for i, issue := range issues {
		if used[i] {
			continue
		}
		// Several identical findings on an annotated line are tolerated.
		if covered(wants, issue) {
			continue
		}
		problems = append(problems, fmt.Sprintf("unexpected issue %s at %s:%d: %s", issue.ID, issue.Location.File, issue.Location.Line, issue.Description))
	}
	return problems
}

func covered(wants []Expectation, issue result.Issue) bool {
	for _, want := range wants {
		if want.RuleID == issue.ID && want.Line == issue.Location.Line && sameFile(issue.Location.File, want.File) {
			return true
		}
	}
	return false
}

func sameFile(issueFile, wantFile string) bool {
	issueFile, wantFile = filepath.ToSlash(issueFile), filepath.ToSlash(wantFile)
	return issueFile == wantFile || strings.HasSuffix(issueFile, "/"+wantFile)
}

func sortIssues(issues []result.Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i].Location, issues[j].Location
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
}

// FilterByID returns the issues with the given rule ID.
func FilterByID(issues []result.Issue, id string) []result.Issue {
	var out []result.Issue
	for _, issue := range issues {
		if issue.ID == id {
			out = append(out, issue)
		}
	}
	return out
}

// ApplyFixes applies the suggested fixes of issues to src. Edits are applied by byte
// offset when available, otherwise by line/column; overlapping edits are skipped.
func ApplyFixes(src string, issues []result.Issue) (string, error) {
	type span struct {
		start, end int
		text       string
	}
	var spans []span
	for _, issue := range issues {
		if issue.Fix == nil {
			continue
		}
		for _, edit := range issue.Fix.Edits {
			start, end := edit.StartOffset, edit.EndOffset
			if start == 0 && end == 0 && edit.StartLine > 0 {
				var err error
				if start, err = offsetOf(src, edit.StartLine, edit.StartColumn); err != nil {
					return "", err
				}
				if end, err = offsetOf(src, edit.EndLine, edit.EndColumn); err != nil {
					return "", err
				}
			}
			if start < 0 || end < start || end > len(src) {
				return "", fmt.Errorf("edit out of range: %d-%d", start, end)
			}
			spans = append(spans, span{start, end, edit.NewText})
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue
		}
		b.WriteString(src[last:s.start])
		b.WriteString(s.text)
		last = s.end
	}
	b.WriteString(src[last:])
	return b.String(), nil
}

func offsetOf(src string, line, column int) (int, error) {
	if line < 1 || column < 1 {
		return 0, fmt.Errorf("invalid position %d:%d", line, column)
	}
	offset := 0
	for l := 1; l < line; l++ {
		idx := strings.IndexByte(src[offset:], '\n')
		if idx < 0 {
			return 0, fmt.Errorf("line %d out of range", line)
		}
		offset += idx + 1
	}
	return offset + column - 1, nil
}

// ApplyFixesAndCompare applies the fixes of issues to src and compares with expectedGolden.
func ApplyFixesAndCompare(t testing.TB, src string, issues []result.Issue, expectedGolden string) {
	t.Helper()
	got, err := ApplyFixes(src, issues)
	if err != nil {
		t.Fatalf("apply fixes: %v", err)
	}
	if got != expectedGolden {
		t.Errorf("fixed source mismatch\n--- got ---\n%s\n--- want ---\n%s", got, expectedGolden)
	}
}
