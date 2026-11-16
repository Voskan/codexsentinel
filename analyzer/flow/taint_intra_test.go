package flow_test

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

const intraHeader = `package app

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

`

func runIntra(t *testing.T, body string) {
	t.Helper()
	testutil.RunTaintBothModes(t, map[string]string{"app.go": intraHeader + body}, nil)
}

func TestIntraConcatenation(t *testing.T) {
	t.Parallel()
	runIntra(t, `func handler(w http.ResponseWriter, r *http.Request) {
	q := "SELECT * FROM u WHERE name = '" + r.FormValue("name") + "'"
	db.Query(q) // want "sql-injection"
	_ = fmt.Sprint
}
`)
}

func TestIntraSprintfVarargs(t *testing.T) {
	t.Parallel()
	runIntra(t, `func handler(w http.ResponseWriter, r *http.Request) {
	q := fmt.Sprintf("SELECT * FROM u WHERE name = '%s'", r.FormValue("name"))
	db.Query(q) // want "sql-injection"
	id := len(r.FormValue("id"))
	db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %d", id))
}
`)
}

func TestIntraPhi(t *testing.T) {
	t.Parallel()
	runIntra(t, `func handler(w http.ResponseWriter, r *http.Request) {
	var q string
	if r.Method == "GET" {
		q = "SELECT 1"
	} else {
		q = r.FormValue("x")
	}
	db.Query(q) // want "sql-injection"
	_ = fmt.Sprint
}
`)
}

func TestIntraFieldSensitive(t *testing.T) {
	t.Parallel()
	runIntra(t, `type filterDTO struct {
	Filter    string
	SafeField string
}

func handler(w http.ResponseWriter, r *http.Request) {
	dto := &filterDTO{SafeField: "name"}
	dto.Filter = r.FormValue("f")
	db.Query("SELECT * FROM u WHERE " + dto.Filter) // want "sql-injection"
	db.Query("SELECT * FROM u ORDER BY " + dto.SafeField)
	_ = fmt.Sprint
}
`)
}

func TestIntraClosure(t *testing.T) {
	t.Parallel()
	runIntra(t, `func handler(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("q")
	func() {
		db.Query("SELECT * FROM u WHERE x = " + input) // want "sql-injection"
	}()
	_ = fmt.Sprint
}
`)
}

func TestIntraParameterizedQueryIsSafe(t *testing.T) {
	t.Parallel()
	runIntra(t, `func handler(w http.ResponseWriter, r *http.Request) {
	db.Query("SELECT * FROM u WHERE name = $1", r.FormValue("name"))
	_ = fmt.Sprint
}
`)
}

func TestIntraTraceAndPositions(t *testing.T) {
	t.Parallel()
	issues := testutil.RunTaintOnFiles(t, map[string]string{"app.go": intraHeader + `func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	db.Query("SELECT " + name) // want "sql-injection"
	_ = fmt.Sprint
}
`}, nil, flow.Options{})
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	issue := issues[0]
	if issue.Location.Line != 13 || issue.Location.Column == 0 || issue.Location.Function != "handler" {
		t.Fatalf("unexpected location %+v", issue.Location)
	}
	if len(issue.Trace) < 2 || issue.Trace[0].Kind != "source" || issue.Trace[len(issue.Trace)-1].Kind != "sink" {
		t.Fatalf("unexpected trace %+v", issue.Trace)
	}
	if issue.Trace[0].Location.Line != 12 || issue.CWE != "CWE-89" {
		t.Fatalf("unexpected source step %+v", issue.Trace[0])
	}
}
