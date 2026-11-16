package metrics

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
)

func loadWorkspace(t *testing.T, files map[string]string) *workspace.Workspace {
	t.Helper()
	dir := writeModule(t, files)
	cfg := config.NewDefaultConfig()
	ws, err := workspace.Load(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

func parseSource(t *testing.T, src string) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fset, []*ast.File{file}
}

func onlyMetrics() config.MetricsConfig {
	return config.MetricsConfig{Enable: true}
}

func issueIDs(issues []result.Issue) map[string]int {
	ids := map[string]int{}
	for _, issue := range issues {
		ids[issue.ID]++
	}
	return ids
}

func TestGlobalsSkipIdiomaticImmutableValues(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"lib/lib.go": `package lib

import (
	"embed"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

const Max = 10

var ErrBad = errors.New("bad")

var errWrapped = fmt.Errorf("wrapped: %w", ErrBad)

var re = regexp.MustCompile("a+")

//go:embed lib.go
var sources embed.FS

var mu sync.Mutex

var _ fmt.Stringer = (*named)(nil)

var lookup = map[string]int{"a": 1}

var GlobalCache = map[string]string{}

type named struct{}

func (*named) String() string { return fmt.Sprint(Max, re, lookup["a"], errWrapped, &mu, sources) }
`})
	cfg := onlyMetrics()
	cfg.EnableGlobals = true
	issues := Run(ws, nil, cfg)
	if len(issues) != 1 || issues[0].ID != "global-variable" || !strings.Contains(issues[0].Description, "GlobalCache") {
		t.Fatalf("want exactly one finding for GlobalCache, got %+v", issues)
	}
}

func TestGlobalsReportWrittenState(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"lib/lib.go": `package lib

var counter int

var limits = map[string]int{"a": 1}

var defaults = map[string]int{"b": 2}

func init() { defaults["c"] = 3 }

func Bump() int {
	counter++
	limits["b"] = 2
	return counter + defaults["b"]
}
`})
	var names []string
	for _, g := range AnalyzeGlobals(ws) {
		names = append(names, g.Name+": "+g.Reason)
	}
	want := []string{"counter: modified in Bump", "limits: modified in Bump"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("globals = %v, want %v", names, want)
	}
}

func duplicatedSource(lines int) string {
	var b strings.Builder
	b.WriteString("package p\n\n")
	for _, name := range []string{"First", "Second"} {
		fmt.Fprintf(&b, "func %s(x int) int {\n", name)
		for i := 0; i < lines-3; i++ {
			fmt.Fprintf(&b, "\tx += %d\n", i)
		}
		b.WriteString("\treturn x\n}\n\n")
	}
	return b.String()
}

func TestDuplicationRespectsMinimumLength(t *testing.T) {
	fset, files := parseSource(t, duplicatedSource(4))
	if got := AnalyzeDuplicates(fset, files, 10); len(got) != 0 {
		t.Fatalf("short functions reported as duplicates: %+v", got)
	}
	fset, files = parseSource(t, duplicatedSource(15))
	got := AnalyzeDuplicates(fset, files, 10)
	if len(got) != 1 || len(got[0].Funcs) != 2 || got[0].LOC != 15 {
		t.Fatalf("want one duplicate block of two 15-line functions, got %+v", got)
	}
}

func TestDuplicationReportsOneGroupFinding(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"p/p.go": duplicatedSource(15)})
	cfg := onlyMetrics()
	cfg.EnableDuplication, cfg.MinDuplicateLOC = true, 10
	issues := Run(ws, nil, cfg)
	if len(issues) != 1 || issues[0].Location.Line != 3 || !strings.Contains(issues[0].Description, "also in Second (p/p.go:19)") {
		t.Fatalf("unexpected duplication findings: %+v", issues)
	}
}

func complexSource() string {
	var b strings.Builder
	b.WriteString("package p\n\nfunc Branchy(x int) int {\n")
	for i := 0; i < 17; i++ {
		fmt.Fprintf(&b, "\tif x == %d {\n\t\tx++\n\t}\n", i)
	}
	b.WriteString("\treturn x\n}\n\nfunc Long() int {\n\tx := 0\n")
	for i := 0; i < 90; i++ {
		b.WriteString("\tx++\n")
	}
	b.WriteString("\treturn x\n}\n")
	return b.String()
}

func TestComplexityAndSizeThresholds(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"p/p.go": complexSource()})
	fset, files := parseSource(t, complexSource())
	if got := AnalyzeComplexity(fset, files); got[0].Name != "Branchy" || got[0].Complexity != 18 {
		t.Fatalf("complexity = %+v", got)
	}

	strict := onlyMetrics()
	strict.MaxCyclomatic, strict.MaxFunctionLOC = 15, 80
	if ids := issueIDs(Run(ws, nil, strict)); ids["high-complexity"] != 1 || ids["large-function"] != 1 {
		t.Fatalf("strict thresholds: %v", ids)
	}

	relaxed := onlyMetrics()
	relaxed.MaxCyclomatic, relaxed.MaxFunctionLOC = 20, 100
	if issues := Run(ws, nil, relaxed); len(issues) != 0 {
		t.Fatalf("relaxed thresholds should report nothing, got %+v", issues)
	}
}

func TestFileSizeThreshold(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"p/p.go": complexSource()})
	cfg := onlyMetrics()
	cfg.MaxFileLOC = 50
	issues := Run(ws, nil, cfg)
	if len(issues) != 1 || issues[0].ID != "large-file" || issues[0].Location.Line != 1 {
		t.Fatalf("file size findings: %+v", issues)
	}
	cfg.MaxFileLOC = 600
	if issues := Run(ws, nil, cfg); len(issues) != 0 {
		t.Fatalf("file below threshold reported: %+v", issues)
	}
}

func TestRunDisabled(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"p/p.go": complexSource()})
	cfg := config.NewDefaultConfig().Metrics
	cfg.Enable = false
	if issues := Run(ws, nil, cfg); len(issues) != 0 {
		t.Fatalf("disabled metrics reported %d issues", len(issues))
	}
}
