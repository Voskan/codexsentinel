package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func TestConstantLookupTables(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"context"
	"database/sql"
	"net/http"
)

var sortColumns = map[string]string{"email": "email", "created": "created_at"}

var orderings = []string{"ASC", "DESC"}

var webhooks = map[string]string{"billing": "https://billing.example.com/hook"}

// mutable is changed at run time, so its values are not constant.
var mutable = map[string]string{"a": "a"}

func Register(k, v string) { mutable[k] = v }

// leaked is passed to a function that may change it.
var leaked = map[string]string{"a": "a"}

func init() { fill(leaked) }

func fill(m map[string]string) { m["b"] = "b" }

func Users(ctx context.Context, db *sql.DB, r *http.Request) {
	col, ok := sortColumns[r.URL.Query().Get("sort")]
	if !ok {
		return
	}
	dir := orderings[len(r.URL.Query().Get("d"))%2]
	_, _ = db.QueryContext(ctx, "SELECT id FROM users ORDER BY "+col+" "+dir)

	m := mutable[r.URL.Query().Get("sort")]
	_, _ = db.QueryContext(ctx, "SELECT id FROM users ORDER BY "+m) // want "sql-injection"

	l := leaked[r.URL.Query().Get("sort")]
	_, _ = db.QueryContext(ctx, "SELECT id FROM users ORDER BY "+l) // want "sql-injection"
}

func Ping(ctx context.Context, name string) error {
	url, ok := webhooks[name]
	if !ok {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func PingAny(ctx context.Context, name string) error {
	url := mutable[name]
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) // want "ssrf"
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
`}, registerInjectionRules)
}
