package testutil

import (
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
)

// AnalyzeTaint builds SSA for a fixture and runs the taint engine with reg
// (nil selects the built-in registry). Issue paths are relative to the fixture.
func AnalyzeTaint(t testing.TB, fx *Fixture, reg *flow.Registry, opts flow.Options) []result.Issue {
	t.Helper()
	return analyzeBundle(fx, buildBundle(t, fx), reg, opts)
}

func buildBundle(t testing.TB, fx *Fixture) *codessa.GraphBundle {
	t.Helper()
	bundle, err := codessa.BuildFromWorkspace(fx.Workspace)
	if err != nil {
		t.Fatalf("build SSA: %v", err)
	}
	return bundle
}

// RunTaintBothModes checks `// want` annotations in both intraprocedural and
// interprocedural modes, building SSA only once.
func RunTaintBothModes(t testing.TB, files map[string]string, reg *flow.Registry) {
	t.Helper()
	fx := LoadFixture(t, files, nil)
	bundle := buildBundle(t, fx)
	for _, inter := range []bool{false, true} {
		CheckExpectations(t, files, analyzeBundle(fx, bundle, reg, flow.Options{Interprocedural: inter}))
	}
}

func analyzeBundle(fx *Fixture, bundle *codessa.GraphBundle, reg *flow.Registry, opts flow.Options) []result.Issue {
	issues := flow.NewEngine(bundle, reg, opts).Run()
	for i := range issues {
		issues[i].Location.File = relativeTo(fx.Dir, issues[i].Location.File)
		for j := range issues[i].Trace {
			issues[i].Trace[j].Location.File = relativeTo(fx.Dir, issues[i].Trace[j].Location.File)
		}
	}
	return issues
}

// RunTaintOnFiles runs the taint engine on an in-memory module and checks
// `// want` annotations.
func RunTaintOnFiles(t testing.TB, files map[string]string, reg *flow.Registry, opts flow.Options) []result.Issue {
	t.Helper()
	fx := LoadFixture(t, files, nil)
	issues := AnalyzeTaint(t, fx, reg, opts)
	CheckExpectations(t, files, issues)
	return issues
}

func relativeTo(dir, file string) string {
	if dir == "" || !filepath.IsAbs(file) {
		return file
	}
	if rel, err := filepath.Rel(dir, file); err == nil {
		return filepath.ToSlash(rel)
	}
	return file
}
