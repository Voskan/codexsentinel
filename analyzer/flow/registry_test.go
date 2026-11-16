package flow_test

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
	"github.com/Voskan/codexsentinel/config"
)

func runRegistry(t *testing.T, src string) {
	t.Helper()
	testutil.RunTaintOnFiles(t, map[string]string{"app.go": src}, nil, flow.Options{})
}

func TestRegistrySQLContextArgumentIndex(t *testing.T) {
	runRegistry(t, `package app

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db.QueryContext(ctx, "SELECT * FROM u WHERE id = "+r.PathValue("id")) // want "sql-injection"
	db.QueryContext(ctx, "SELECT * FROM u WHERE id = $1", r.PathValue("id"))
	tx, _ := db.Begin()
	tx.Exec("DELETE FROM u WHERE id = " + r.URL.Query().Get("id")) // want "sql-injection"
}
`)
}

func TestRegistryResponseWriterInvoke(t *testing.T) {
	runRegistry(t, `package app

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.FormValue("msg"))) // want "xss"
	w.Write([]byte(html.EscapeString(r.FormValue("msg"))))
	fmt.Fprintf(w, "<p>%s</p>", r.FormValue("msg")) // want "xss"
	var buf bytes.Buffer
	buf.Write([]byte(r.FormValue("msg")))
	fmt.Fprintf(&buf, "%s", r.FormValue("msg"))
}
`)
}

func TestRegistryUniversalSanitizer(t *testing.T) {
	runRegistry(t, `package app

import (
	"database/sql"
	"net/http"
	"strconv"
)

func handler(db *sql.DB, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return
	}
	db.Query("SELECT * FROM u WHERE id = " + strconv.Itoa(id))
}
`)
}

func TestRegistryOSRoot(t *testing.T) {
	runRegistry(t, `package app

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	root, _ := os.OpenRoot("/var/data")
	root.Open(r.FormValue("file"))
	os.Open(filepath.Clean(r.FormValue("file"))) // want "path-traversal"
	os.Open(filepath.Join("/var/data", filepath.Base(r.FormValue("file"))))
}
`)
}

func TestRegistryTemplates(t *testing.T) {
	runRegistry(t, `package app

import (
	"html/template"
	"net/http"
	text "text/template"
)

var htmlTpl = template.Must(template.New("x").Parse("{{.}}"))
var textTpl = text.Must(text.New("x").Parse("{{.}}"))

func handler(w http.ResponseWriter, r *http.Request) {
	htmlTpl.Execute(w, r.FormValue("x"))
	htmlTpl.Execute(w, template.HTML(r.FormValue("x"))) // want "xss"
	textTpl.Execute(w, r.FormValue("x")) // want "xss"
	htmlTpl.Execute(w, template.HTML("<b>static</b>"))
}
`)
}

func TestRegistryCommandAndRedirect(t *testing.T) {
	runRegistry(t, `package app

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.FormValue("cmd")) // want "command-injection"
	exec.Command("git", "status")
	http.Get(r.FormValue("url")) // want "ssrf"
	http.Get("https://api.example.com/items?q=" + r.FormValue("q"))
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound) // want "open-redirect"
	http.Redirect(w, r, "/profile/"+r.FormValue("id"), http.StatusFound)
}
`)
}

func TestRegistryFromConfig(t *testing.T) {
	cfg := config.TaintConfig{
		CustomSources:    []config.CustomSourceSpec{{Package: "example.com/fixture/input", Function: "Read"}},
		CustomSinks:      []config.CustomSinkSpec{{Package: "example.com/fixture/store", Receiver: "*Store", Function: "Raw", CheckArgs: []int{0}, Category: "sql-injection"}},
		CustomSanitizers: []config.CustomSanSpec{{Package: "example.com/fixture/input", Function: "Clean", Categories: []string{"sql-injection"}}},
	}
	files := map[string]string{
		"input/input.go": `package input

func Read() string { return "" }

func Clean(s string) string { return s }
`,
		"store/store.go": `package store

type Store struct{}

func (*Store) Raw(q string) {}
`,
		"app.go": `package app

import (
	"example.com/fixture/input"
	"example.com/fixture/store"
)

func run(s *store.Store) {
	s.Raw("SELECT " + input.Read()) // want "sql-injection"
	s.Raw("SELECT " + input.Clean(input.Read()))
}
`,
	}
	testutil.RunTaintOnFiles(t, files, flow.RegistryFromConfig(cfg), flow.Options{})
}
