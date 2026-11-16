package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func registerResilience(ctx *analyzer.AnalyzerContext) {
	RegisterAPISecurityRule(ctx)
	RegisterInsecureDesignRule(ctx)
	RegisterDataIntegrityRule(ctx)
	RegisterAccessControlRule(ctx)
}

func TestResilienceIntegrityBodyLimits(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"body.go": `package app

import (
	"io"
	"net/http"
	"os"
	"strconv"
)

func unbounded(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body) // want "http-unbounded-body-read"
	_ = data
}

func limited(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	data, _ := io.ReadAll(r.Body)
	_ = data
}

func file(f *os.File) []byte {
	data, _ := io.ReadAll(f)
	return data
}

func alloc(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	buf := make([]byte, n) // want "untrusted-slice-allocation"
	_ = buf
}

func boundedAlloc(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n < 0 || n > 4096 {
		return
	}
	buf := make([]byte, n)
	_ = buf
}
`}, registerResilience)
}

func TestResilienceIntegrityContext(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"ctx.go": `package app

import (
	"context"
	"database/sql"
	"net/http"
	"os/exec"
	"time"
)

var db *sql.DB

func Handle(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT 1") // want "context-propagation-missing"
	_ = rows
}

func HandleCtx(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.QueryContext(r.Context(), "SELECT 1")
	_ = rows
}

func Detached(ctx context.Context) {
	_, _ = db.ExecContext(context.Background(), "DELETE FROM cache") // want "context-propagation-missing"
	_ = exec.Command("true").Run() // want "context-propagation-missing"
}

func NoContext() {
	rows, _ := db.Query("SELECT 1")
	_ = rows
	_ = exec.Command("true").Run()
}

func clients() {
	_ = &http.Client{} // want "http-client-unsafe"
	_ = &http.Client{Timeout: 10 * time.Second}
	_ = &http.Client{
		Timeout: time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { // want "http-client-unsafe"
			req.Header = via[0].Header
			return nil
		},
	}
}

func proxy(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, r.URL.Query().Get("callback"), nil)
	req.Header.Set("Authorization", "Bearer secret") // want "http-client-unsafe"
	_, _ = http.DefaultClient.Do(req)
}

func fixedProxy(w http.ResponseWriter, r *http.Request) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.example.com/v1", nil)
	req.Header.Set("Authorization", "Bearer secret")
	_, _ = http.DefaultClient.Do(req)
}
`}, registerResilience)
}

func TestResilienceIntegrityArchives(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"zip.go": `package app

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
)

func extract(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		out, err := os.Create(filepath.Join(dest, f.Name)) // want "archive-zip-slip"
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		_, err = io.Copy(out, rc) // want "archive-decompression-bomb"
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractSafe(zr *zip.Reader, root *os.Root) error {
	for _, f := range zr.File {
		out, err := root.Create(f.Name)
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 10<<20))
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func untar(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(target, 0o750) // want "archive-zip-slip"
			continue
		}
		f, _ := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o600) // want "archive-zip-slip"
		_, _ = io.Copy(f, tr) // want "archive-decompression-bomb"
		f.Close()
	}
}

func copyPlain(dst io.Writer, src *os.File) {
	_, _ = io.Copy(dst, src)
}
`}, registerResilience)
}

func TestResilienceIntegrityGob(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"gob.go": `package app

import (
	"encoding/gob"
	"encoding/json"
	"net/http"
)

type payload struct{ Name string }

func gobHandler(w http.ResponseWriter, r *http.Request) {
	var p payload
	_ = gob.NewDecoder(r.Body).Decode(&p) // want "unsafe-gob-decode"
}

func jsonHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var p payload
	_ = json.NewDecoder(r.Body).Decode(&p)
}
`}, registerResilience)
}

func TestResilienceIntegrityIDOR(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"idor.go": `package app

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func deleteDoc(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, _ = db.ExecContext(r.Context(), "DELETE FROM documents WHERE id = $1", id) // want "idor-unscoped-mutation"
}

func deleteOwnDoc(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, _ = db.ExecContext(r.Context(), "DELETE FROM documents WHERE id = $1 AND owner_id = $2", id, currentUser(r))
}

func updateChecked(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canEdit(r, id) {
		return
	}
	_, _ = db.ExecContext(r.Context(), "UPDATE documents SET title = $1 WHERE id = $2", r.FormValue("t"), id)
}

func listDocs(w http.ResponseWriter, r *http.Request) {
	_, _ = db.ExecContext(r.Context(), "DELETE FROM sessions WHERE expires_at < now()")
}

func currentUser(r *http.Request) string         { return r.Header.Get("X-User") }
func canEdit(r *http.Request, id string) bool { return id != "" }
`}, registerResilience)
}
