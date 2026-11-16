package flow_test

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

var layeredFiles = map[string]string{
	"handler/handler.go": `package handler

import (
	"net/http"
	"strconv"

	"example.com/fixture/service"
)

type Handler struct{ Svc *service.UserService }

func query(r *http.Request, key string) string { return r.URL.Query().Get(key) }

func parseID(raw string) (int, error) { return strconv.Atoi(raw) }

func (h *Handler) Unsafe(w http.ResponseWriter, r *http.Request) {
	h.Svc.Search(r.Context(), query(r, "filter"))
}

func (h *Handler) Safe(w http.ResponseWriter, r *http.Request) {
	h.Svc.SearchSafe(r.Context(), query(r, "filter"))
}

func (h *Handler) ByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Query().Get("id"))
	if err != nil {
		return
	}
	h.Svc.ByID(r.Context(), id)
}
`,
	"service/service.go": `package service

import (
	"context"
	"strconv"
)

type UserRepository interface {
	FindUnsafe(ctx context.Context, filter string) error
	FindSafe(ctx context.Context, filter string) error
	FindRaw(ctx context.Context, where string) error
}

type UserService struct{ Repo UserRepository }

func (s *UserService) Search(ctx context.Context, filter string) error {
	return s.Repo.FindUnsafe(ctx, filter)
}

func (s *UserService) SearchSafe(ctx context.Context, filter string) error {
	return s.Repo.FindSafe(ctx, filter)
}

func (s *UserService) ByID(ctx context.Context, id int) error {
	return s.Repo.FindRaw(ctx, "id = "+strconv.Itoa(id))
}
`,
	"postgres/repo.go": `package postgres

import (
	"context"
	"database/sql"

	"example.com/fixture/service"
)

type Repo struct{ DB *sql.DB }

var _ service.UserRepository = (*Repo)(nil)

func (r *Repo) FindUnsafe(ctx context.Context, filter string) error {
	_, err := r.DB.QueryContext(ctx, "SELECT * FROM users WHERE name LIKE '"+filter+"'") // want "sql-injection"
	return err
}

func (r *Repo) FindSafe(ctx context.Context, filter string) error {
	_, err := r.DB.QueryContext(ctx, "SELECT * FROM users WHERE name LIKE $1", filter)
	return err
}

func (r *Repo) FindRaw(ctx context.Context, where string) error {
	_, err := r.DB.QueryContext(ctx, "SELECT * FROM users WHERE "+where)
	return err
}
`,
	"main.go": `package main

import (
	"database/sql"
	"net/http"

	"example.com/fixture/handler"
	"example.com/fixture/postgres"
	"example.com/fixture/service"
)

func main() {
	h := &handler.Handler{Svc: &service.UserService{Repo: &postgres.Repo{DB: &sql.DB{}}}}
	http.HandleFunc("/unsafe", h.Unsafe)
	http.HandleFunc("/safe", h.Safe)
	http.HandleFunc("/id", h.ByID)
}
`,
}

func TestInterproceduralLayers(t *testing.T) {
	t.Parallel()
	issues := testutil.RunTaintOnFiles(t, layeredFiles, nil, flow.Options{Interprocedural: true})
	if len(issues) != 1 {
		t.Fatalf("expected one finding, got %d", len(issues))
	}
	trace := issues[0].Trace
	if len(trace) < 3 {
		t.Fatalf("expected a multi-step trace, got %+v", trace)
	}
	if trace[0].Kind != "source" || trace[0].Location.File != "handler/handler.go" {
		t.Fatalf("trace must start at the handler source: %+v", trace[0])
	}
	last := trace[len(trace)-1]
	if last.Kind != "sink" || last.Location.File != "postgres/repo.go" {
		t.Fatalf("trace must end at the repository sink: %+v", last)
	}
	var sawService bool
	for _, step := range trace {
		if step.Location.File == "service/service.go" {
			sawService = true
		}
	}
	if !sawService {
		t.Fatalf("trace should pass through the service layer: %+v", trace)
	}
}

func TestIntraproceduralMissesLayeredFlow(t *testing.T) {
	t.Parallel()
	fx := testutil.LoadFixture(t, layeredFiles, nil)
	if issues := testutil.AnalyzeTaint(t, fx, nil, flow.Options{}); len(issues) != 0 {
		t.Fatalf("intraprocedural mode should not follow calls, got %+v", issues)
	}
}

func TestInterproceduralSanitizerWrapperAndRecursion(t *testing.T) {
	t.Parallel()
	testutil.RunTaintOnFiles(t, map[string]string{"app.go": `package app

import (
	"html"
	"net/http"
	"os/exec"
)

func clean(s string) string { return html.EscapeString(s) }

func render(w http.ResponseWriter, s string) { w.Write([]byte(s)) } // want "xss"

func run(name string, depth int) {
	if depth > 0 {
		run(name, depth-1)
		return
	}
	exec.Command(name).Run() // want "command-injection"
}

func fill(dst *string, r *http.Request) { *dst = r.FormValue("x") }

func handler(w http.ResponseWriter, r *http.Request) {
	render(w, clean(r.FormValue("a")))
	render(w, r.FormValue("b"))
	run(r.FormValue("c"), 3)
	var v string
	fill(&v, r)
	exec.Command(v)  // want "command-injection"
}
`}, nil, flow.Options{Interprocedural: true})
}
