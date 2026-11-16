package arch

import (
	"reflect"
	"strings"
	"testing"

	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/packages"
)

func bigStruct() string {
	var b strings.Builder
	b.WriteString("package service\n\ntype Big struct{ n int }\n\n")
	for i := 0; i < 18; i++ {
		b.WriteString("func (b *Big) M" + string(rune('A'+i)) + "() int { return b.n }\n")
	}
	return b.String()
}

func cleanArchFixture(t *testing.T) map[string][]string {
	t.Helper()
	fx := testutil.LoadFixture(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"internal/domain/order.go": `package domain

import "net/http"

type Order struct{ ID string; Total int }

func CalculateDiscount(r *http.Request) int { return len(r.URL.Path) }
`,
		"internal/repository/repo.go": `package repository

import "example.com/app/internal/domain"

func Find(id string) domain.Order { return domain.Order{ID: id} }
`,
		"internal/service/service.go": `package service

import (
	"example.com/app/internal/domain"
	"example.com/app/internal/repository"
)

func Load(id string) domain.Order { return repository.Find(id) }
`,
		"internal/service/big.go": bigStruct(),
		"internal/handler/good/good.go": `package good

import (
	"net/http"

	"example.com/app/internal/service"
)

func Get(w http.ResponseWriter, r *http.Request) { _ = service.Load(r.PathValue("id")) }
`,
		"internal/handler/bad/bad.go": `package bad

import (
	"net/http"

	"example.com/app/internal/repository"
)

func Get(w http.ResponseWriter, r *http.Request) { _ = repository.Find(r.PathValue("id")) }
`,
	}, nil)
	bundle, err := codessa.BuildFromWorkspace(fx.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NewDefaultConfig().Architecture
	got := map[string][]string{}
	for _, issue := range RunAll(fx.Workspace, bundle, cfg) {
		got[issue.ID] = append(got[issue.ID], issue.Location.PackagePath+": "+issue.Description)
	}
	return got
}

func TestArchCleanArchitecture(t *testing.T) {
	t.Parallel()
	got := cleanArchFixture(t)

	layer := got["arch-layer-violation"]
	if len(layer) != 1 || !strings.HasPrefix(layer[0], "example.com/app/internal/handler/bad:") || !strings.Contains(layer[0], `layer "repository"`) {
		t.Errorf("layer violations = %q", layer)
	}
	leaks := got["arch-boundary-type-leak"]
	if len(leaks) != 1 || !strings.Contains(leaks[0], "Transport type '*http.Request' leaked into domain layer via CalculateDiscount") {
		t.Errorf("boundary leaks = %q", leaks)
	}
	gods := got["arch-god-struct"]
	if len(gods) != 1 || !strings.Contains(gods[0], "Struct Big has 18 methods") {
		t.Errorf("god structs = %q", gods)
	}
	if len(got) != 3 {
		t.Errorf("unexpected issue kinds: %v", got)
	}
}

func TestArchImportOnlyWithoutCallGraph(t *testing.T) {
	t.Parallel()
	fx := testutil.LoadFixture(t, map[string]string{
		"go.mod":         "module example.com/app\n\ngo 1.24\n",
		"db/db.go":       "package db\n\nimport \"database/sql\"\n\nfunc Open() (*sql.DB, error) { return sql.Open(\"x\", \"\") }\n",
		"api/api.go":     "package api\n\nimport (\n\t\"database/sql\"\n\n\t\"example.com/app/db\"\n)\n\ntype Server struct{ DB *sql.DB }\n\nvar _ = db.Open\n",
		"model/model.go": "package model\n\ntype User struct{ Name string }\n",
		"service/svc.go": "package service\n\nimport \"example.com/app/model\"\n\nfunc Name(u model.User) string { return u.Name }\n",
	}, nil)
	issues := RunAll(fx.Workspace, nil, config.ArchConfig{Enable: true, CheckBoundaries: true})
	var ids []string
	for _, i := range issues {
		ids = append(ids, i.ID+" "+i.Location.PackagePath)
	}
	want := []string{"arch-layer-violation example.com/app/api", "arch-boundary-type-leak example.com/app/api"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("issues = %v, want %v", ids, want)
	}
	if !strings.Contains(issues[1].Description, "Database type '*sql.DB' leaked into delivery layer via Server.DB") {
		t.Fatalf("unexpected message: %s", issues[1].Description)
	}
}

func TestArchConfiguredLayers(t *testing.T) {
	l := NewLayering(config.ArchConfig{
		Layers:      map[string][]string{"web": {"internal/web/*"}, "core": {"/core"}},
		AllowedDeps: map[string][]string{"web": {"core"}},
	})
	if l.LayerOf("internal/web/users") != "web" || l.LayerOf("pkg/core") != "core" || l.LayerOf("cmd/tool") != "" {
		t.Fatal("configured layers not resolved")
	}
	if !l.Allowed("web", "core") || l.Allowed("core", "web") || !l.Allowed("core", "core") {
		t.Fatal("configured dependencies not applied")
	}
	if d := NewLayering(config.ArchConfig{}); d.Configured || d.LayerOf("internal/handlers/user") != "delivery" || d.LayerOf("internal/domain/service") != "service" {
		t.Fatal("default layers not resolved")
	}
}

func TestArchImportCycles(t *testing.T) {
	a := &packages.Package{PkgPath: "example.com/a", Imports: map[string]*packages.Package{}}
	b := &packages.Package{PkgPath: "example.com/b", Imports: map[string]*packages.Package{}}
	c := &packages.Package{PkgPath: "example.com/c", Imports: map[string]*packages.Package{}}
	d := &packages.Package{PkgPath: "example.com/d", Imports: map[string]*packages.Package{}}
	a.Imports[b.PkgPath] = b
	b.Imports[c.PkgPath] = c
	c.Imports[a.PkgPath] = a
	d.Imports[a.PkgPath] = a
	cycles := AnalyzeImportCycles([]*packages.Package{d, a, b, c, a})
	if len(cycles) != 1 || !reflect.DeepEqual(cycles[0].Packages, []string{"example.com/a", "example.com/b", "example.com/c", "example.com/a"}) {
		t.Fatalf("cycles = %+v", cycles)
	}
	if !HasCycleFor("example.com/b", cycles) || HasCycleFor("example.com/d", cycles) {
		t.Fatal("HasCycleFor mismatch")
	}
	if len(AnalyzeImportCycles([]*packages.Package{d})) != 1 {
		t.Fatal("cycle reachable through imports not found")
	}
}
