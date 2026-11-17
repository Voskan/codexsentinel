package ssa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"github.com/Voskan/codexsentinel/v2/config"
	"golang.org/x/tools/go/ssa"
)

func buildBundle(t *testing.T, files map[string]string) *GraphBundle {
	t.Helper()
	bundle, err := BuildFromWorkspace(loadWorkspace(t, files))
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	return bundle
}

func loadWorkspace(t *testing.T, files map[string]string) *workspace.Workspace {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module example.com/app\n\ngo 1.24\n"
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.NewDefaultConfig()
	ws, err := workspace.Load(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	return ws
}

func TestBuildFromWorkspaceStopsWhenCancelled(t *testing.T) {
	ws := loadWorkspace(t, map[string]string{"main.go": "package main\n\nimport \"net/http\"\n\nfunc main() { _ = http.ListenAndServe(\":8080\", nil) }\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if bundle, err := BuildFromWorkspaceContext(ctx, ws); !errors.Is(err, context.Canceled) || bundle != nil {
		t.Fatalf("BuildFromWorkspaceContext after cancel = %v, %v; want nil, context.Canceled", bundle, err)
	}
	if _, err := BuildFromWorkspaceContext(context.Background(), ws); err != nil {
		t.Fatalf("BuildFromWorkspaceContext = %v", err)
	}
}

func findFunc(t *testing.T, g *GraphBundle, name string) *ssa.Function {
	t.Helper()
	for _, fn := range g.TargetFunctions() {
		if fn.String() == name {
			return fn
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func TestBuildFromWorkspaceGenerics(t *testing.T) {
	g := buildBundle(t, map[string]string{"main.go": `package main

func Transform[T any](v T) T { return v }

func main() {
	_ = Transform(1)
	_ = Transform("x")
}
`})
	var instances int
	for _, fn := range g.TargetFunctions() {
		if fn.Origin() != nil && fn.Origin().Name() == "Transform" {
			instances++
		}
	}
	if instances < 2 {
		t.Fatalf("expected instantiated Transform functions, got %d", instances)
	}
	main := findFunc(t, g, "example.com/app.main")
	callees := g.Callees(main)
	if len(callees) == 0 {
		t.Fatal("main has no callees")
	}
}

func TestVTAPrecision(t *testing.T) {
	g := buildBundle(t, map[string]string{"main.go": `package main

type Store interface{ Save() }

type SafeStore struct{}

func (SafeStore) Save() {}

type UnusedStore struct{}

func (UnusedStore) Save() {}

func persist(store Store) { store.Save() }

func main() { persist(SafeStore{}) }
`})
	persist := findFunc(t, g, "example.com/app.persist")
	var names []string
	for _, callee := range g.Callees(persist) {
		names = append(names, callee.String())
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "SafeStore).Save") {
		t.Fatalf("expected edge to SafeStore.Save, got %v", names)
	}
	if strings.Contains(joined, "UnusedStore") {
		t.Fatalf("VTA should not resolve to UnusedStore.Save, got %v", names)
	}
}

func TestSCCOrder(t *testing.T) {
	g := buildBundle(t, map[string]string{"main.go": `package main

func A(n int) int {
	if n == 0 {
		return C()
	}
	return B(n - 1)
}

func B(n int) int { return A(n) }

func C() int { return 1 }

func main() { _ = A(3) }
`})
	pos := map[string]int{}
	var ab []*ssa.Function
	for i, scc := range g.SCCs() {
		for _, fn := range scc {
			pos[fn.String()] = i
		}
		if len(scc) == 2 && scc[0].Name() == "A" {
			ab = scc
		}
	}
	if len(ab) != 2 || ab[1].Name() != "B" {
		t.Fatalf("expected SCC [A B], got %v", ab)
	}
	if pos["example.com/app.C"] >= pos["example.com/app.A"] {
		t.Fatal("callee SCC [C] must precede caller SCC [A B]")
	}
	if pos["example.com/app.A"] >= pos["example.com/app.main"] {
		t.Fatal("SCC [A B] must precede main")
	}
}

func TestEffectiveArgs(t *testing.T) {
	g := buildBundle(t, map[string]string{"main.go": `package main

type T struct{}

func (*T) Foo(x int) {}

type I interface{ Foo(x int) }

func plain(x int) {}

func main() {
	plain(1)
	t := &T{}
	t.Foo(2)
	var i I = t
	i.Foo(3)
}
`})
	main := findFunc(t, g, "example.com/app.main")
	checked := 0
	for _, block := range main.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			recv, args := EffectiveArgs(call.Common())
			if len(args) != 1 {
				t.Fatalf("%s: expected one positional argument, got %d", call, len(args))
			}
			switch {
			case call.Common().IsInvoke():
				if recv == nil || args[0].String() != "3:int" {
					t.Fatalf("invoke: recv=%v args=%v", recv, args)
				}
			case call.Common().StaticCallee().Name() == "plain":
				if recv != nil || args[0].String() != "1:int" {
					t.Fatalf("plain: recv=%v args=%v", recv, args)
				}
			case call.Common().StaticCallee().Name() == "Foo":
				if recv == nil || args[0].String() != "2:int" {
					t.Fatalf("method: recv=%v args=%v", recv, args)
				}
			default:
				continue
			}
			checked++
		}
	}
	if checked != 3 {
		t.Fatalf("expected 3 checked calls, got %d", checked)
	}
}

func TestReachableFromAndEntrypoints(t *testing.T) {
	g := buildBundle(t, map[string]string{"main.go": `package main

func used() {}

func unused() {}

func main() { used() }
`})
	reach := g.ReachableFrom(g.Entrypoints())
	if !reach[findFunc(t, g, "example.com/app.used")] {
		t.Fatal("used should be reachable")
	}
	if reach[findFunc(t, g, "example.com/app.unused")] {
		t.Fatal("unused should not be reachable")
	}
}
