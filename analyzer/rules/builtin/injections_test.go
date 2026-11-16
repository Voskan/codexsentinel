package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func registerInjectionRules(ctx *analyzer.AnalyzerContext) {
	RegisterSQLInjectionRule(ctx)
	RegisterCommandExecRule(ctx)
	RegisterXSSRule(ctx)
	RegisterSSRFRule(ctx)
	RegisterPathTraversalRule(ctx)
}

func TestInjectionSQL(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"context"
	"database/sql"
	"fmt"
)

const tableUsers = "users"

type cache struct{}

func (cache) Query(q string) string { return q }

func find(ctx context.Context, db *sql.DB, name string, id int) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'") // want "sql-injection"
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	db.QueryContext(ctx, q) // want "sql-injection"
	db.Query("SELECT * FROM " + tableUsers)
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
	db.Query("SELECT * FROM users WHERE name = ?", name)
	db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)
	base := "SELECT * FROM users"
	base += " ORDER BY id"
	db.Query(base)
	var myCache cache
	myCache.Query("a" + name)
}
`}, registerInjectionRules)
}

func TestInjectionCommand(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"context"
	"os/exec"
)

func run(ctx context.Context, cmd, bin string) {
	exec.Command("sh", "-c", cmd) // want "command-injection"
	exec.CommandContext(ctx, "bash", "-c", "ls "+cmd) // want "command-injection"
	exec.Command(bin, "--version") // want "command-injection"
	exec.Command("git", "status")
	exec.Command("git", "log", cmd)
	exec.Command("sh", "-c", "echo hello")
}
`}, registerInjectionRules)
}

func TestInjectionXSS(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"net/http"
	text "text/template"
)

var page = text.Must(text.New("p").Parse("{{.}}"))

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	w.Write([]byte(name)) // want "xss"
	var buf bytes.Buffer
	buf.Write([]byte(name))
	w.Write([]byte(html.EscapeString(name)))
	w.Write([]byte("<p>static</p>"))
	fmt.Fprintf(w, "<p>%s</p>", name) // want "xss"
	fmt.Fprintf(w, "<p>%d</p>", len(name))
	_ = template.HTML(name) // want "xss"
	_ = template.HTML("<b>ok</b>")
	page.Execute(w, name) // want "xss"
	page.Execute(&buf, name)
}
`}, registerInjectionRules)
}

func TestInjectionSSRF(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"errors"
	"net/http"
	"net/url"
	"os"
)

func fetch(targetURL, id string) {
	http.Get(targetURL) // want "ssrf"
	http.Get("https://api.example.com/v1")
	http.Get("https://api.example.com/v1/items/" + id)
	os.Open(targetURL)
}

func handler(w http.ResponseWriter, r *http.Request) {
	http.Get(r.FormValue("url")) // want "ssrf"
}

func validated(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() != "api.example.com" {
		return errors.New("host not allowed")
	}
	_, err = http.Get(u.String())
	return err
}
`}, registerInjectionRules)
}

func TestInjectionPathTraversal(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	os.ReadFile(r.FormValue("f")) // want "path-traversal"
	os.ReadFile(filepath.Clean(r.FormValue("f"))) // want "path-traversal"
	name := r.URL.Query().Get("name")
	os.Open(filepath.Join("/srv", name)) // want "path-traversal:os.OpenRoot"
	root, _ := os.OpenRoot("/srv")
	root.Open(r.FormValue("f"))
	os.ReadFile(filepath.Join("/srv", filepath.Base(r.FormValue("f"))))
	filepath.Clean(r.FormValue("f"))
	os.ReadFile("/etc/hosts")
}

func local(path string) { os.ReadFile(path) }
`}, registerInjectionRules)
}
