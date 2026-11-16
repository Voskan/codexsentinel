package builtin

import (
	"go/build"
	"slices"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func registerWebProtocols(ctx *analyzer.AnalyzerContext) {
	RegisterCSRFRule(ctx)
	RegisterWebSocketSecurityRule(ctx)
	RegisterGraphQLSecurityRule(ctx)
	RegisterSecurityMisconfigRule(ctx)
	RegisterAuthBypassRule(ctx)
}

func TestWebProtocolsNoKeywordNoise(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import "errors"

var ErrInvalidToken = errors.New("invalid token")

type Message struct {
	Type  string
	Query string
	Data  []byte
	Read  bool
}

func f(m Message, err error, tokenType string) bool {
	ok := true
	if ok {
		m.Read = true
	}
	if m.Type == "query" || m.Query == "" {
		return false
	}
	if tokenType == "Bearer" || err == ErrInvalidToken {
		return true
	}
	return 1 == 1
}
`}, registerWebProtocols)
}

// requireGoRelease skips the test when the Go toolchain that type-checks the
// fixtures predates release (for example "go1.25").
func requireGoRelease(t *testing.T, release string) {
	t.Helper()
	if !slices.Contains(build.Default.ReleaseTags, release) {
		t.Skipf("fixture needs %s or newer", release)
	}
}

func TestWebProtocolsCSRF(t *testing.T) {
	t.Parallel()
	vulnerable := `package app

import "net/http"

func transfer(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("sid"); err != nil {
		return
	}
}

func routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /balance", transfer)
	mux.HandleFunc("POST /transfer", transfer) // want "csrf-missing-protection"
	return mux
}
`
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": vulnerable}, registerWebProtocols)

	t.Run("CrossOriginProtection", func(t *testing.T) {
		requireGoRelease(t, "go1.25")
		protected := vulnerable + `
func server() http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(routes())
}
`
		protected = removeWants(protected)
		testutil.RunRulesOnFiles(t, map[string]string{"app.go": protected}, registerWebProtocols)
	})

	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import "net/http"

func api(w http.ResponseWriter, r *http.Request) { _ = r.Header.Get("Authorization") }

func routes(mux *http.ServeMux) { mux.HandleFunc("POST /api/items", api) }
`}, registerWebProtocols)
}

func TestWebProtocolsWebSocket(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":          "module example.com/fixture\n\ngo 1.24\n\nrequire github.com/gorilla/websocket v1.5.0\n\nreplace github.com/gorilla/websocket => ./stubs/ws\n",
		"stubs/ws/go.mod": "module github.com/gorilla/websocket\n\ngo 1.24\n",
		"stubs/ws/ws.go":  "package websocket\n\nimport \"net/http\"\n\ntype Upgrader struct {\n\tCheckOrigin func(r *http.Request) bool\n}\n",
		"app/app.go": `package app

import (
	"net/http"

	"github.com/gorilla/websocket"
)

const allowed = "https://app.example.com"

var open = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }} // want "websocket-origin-bypass"

var strict = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == allowed }}
`,
	}
	testutil.RunRulesOnFiles(t, files, registerWebProtocols)
}

func TestWebProtocolsServerMisconfig(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"main.go": `package main

import (
	"net/http"
	_ "net/http/pprof" // want "debug-endpoint-exposed"
	"os"
	"time"
)

func cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin")) // want "cors-wildcard-credentials"
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func main() {
	mux := http.NewServeMux()
	http.ListenAndServe(":8080", mux) // want "http-server-missing-timeout"
	_ = &http.Server{Addr: ":8080"} // want "http-server-missing-timeout"
	_ = &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	os.WriteFile("a", nil, 0666) // want "insecure-file-permissions"
	os.WriteFile("b", nil, 0600)
	os.WriteFile("c", nil, 0644)
	os.MkdirAll("d", 0777) // want "insecure-file-permissions"
	os.MkdirAll("e", 0755)
}
`}, registerWebProtocols)
}

func TestWebProtocolsAuth(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
)

func check(sig, expectedSig, token, password string, mac, expectedMAC []byte) bool {
	if sig == expectedSig { // want "auth-non-constant-time-compare"
		return true
	}
	if token == "" {
		return false
	}
	if password == "admin123" { // want "auth-hardcoded-credential"
		return true
	}
	if bytes.Equal(mac, expectedMAC) { // want "auth-non-constant-time-compare"
		return true
	}
	return hmac.Equal(mac, expectedMAC) || subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}
`}, registerWebProtocols)
}

func removeWants(src string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if j := strings.Index(line, "// want"); j >= 0 {
			lines[i] = strings.TrimRight(line[:j], " \t")
		}
	}
	return strings.Join(lines, "\n")
}
