package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
)

const insecure = "package main\n\nimport \"crypto/tls\"\n\nfunc main() {\n\tcfg := &tls.Config{InsecureSkipVerify: true}\n\t_ = cfg\n}\n"

func analyze(ctx context.Context, req Request) ([]result.Issue, error) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	return engine.RunWithOptions(ctx, req.Root, &cfg, engine.Options{Focus: req.Files, Early: req.Early})
}

// client drives a server over pipes.
type client struct {
	t      *testing.T
	in     io.WriteCloser
	out    *bufio.Reader
	nextID int
}

func (c *client) send(v any) {
	c.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c.in, "Content-Length: %d\r\n\r\n%s", len(data), data); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) request(method string, params any) int {
	c.nextID++
	c.send(map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params})
	return c.nextID
}

func (c *client) notify(method string, params any) {
	c.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

type message struct {
	ID     *int            `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// read returns the next framed message; anything else on the stream fails
// the test.
func (c *client) read() message {
	c.t.Helper()
	header, err := c.out.ReadString('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	if !strings.HasPrefix(header, "Content-Length: ") || !strings.HasSuffix(header, "\r\n") {
		c.t.Fatalf("unexpected bytes on the protocol stream: %q", header)
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "Content-Length: ")))
	if err != nil {
		c.t.Fatal(err)
	}
	if blank, _ := c.out.ReadString('\n'); blank != "\r\n" {
		c.t.Fatalf("missing blank line after header: %q", blank)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.out, body); err != nil {
		c.t.Fatal(err)
	}
	var m message
	if err := json.Unmarshal(body, &m); err != nil {
		c.t.Fatalf("%v: %s", err, body)
	}
	return m
}

func (c *client) response(id int) message {
	c.t.Helper()
	for {
		m := c.read()
		if m.ID != nil && *m.ID == id && m.Method == "" {
			return m
		}
	}
}

func (c *client) diagnosticsFor(uri string) []diagnostic {
	c.t.Helper()
	for {
		m := c.read()
		if m.Method != "textDocument/publishDiagnostics" {
			continue
		}
		var p publishDiagnosticsParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			c.t.Fatal(err)
		}
		if p.URI == uri {
			if p.Diagnostics == nil {
				c.t.Fatal("diagnostics must be an array, not null")
			}
			return p.Diagnostics
		}
	}
}

func startServer(t *testing.T) (*client, chan error) {
	t.Helper()
	return startWith(t, &Server{Analyze: analyze})
}

func startWith(t *testing.T, srv *Server) (*client, chan error) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() { inW.Close() })
	return &client{t: t, in: inW, out: bufio.NewReader(outR)}, done
}

func TestLanguageServerLifecycle(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/lsp\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte(insecure), 0o600); err != nil {
		t.Fatal(err)
	}
	c, done := startServer(t)
	uri := pathToURI(mainPath)

	init := c.response(c.request("initialize", map[string]any{"rootUri": pathToURI(dir), "capabilities": map[string]any{}}))
	var initResult struct {
		Capabilities struct {
			TextDocumentSync struct {
				OpenClose bool `json:"openClose"`
				Change    int  `json:"change"`
			} `json:"textDocumentSync"`
			CodeActionProvider any `json:"codeActionProvider"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(init.Result, &initResult); err != nil || !initResult.Capabilities.TextDocumentSync.OpenClose || initResult.Capabilities.CodeActionProvider == nil {
		t.Fatalf("initialize result %s (%v)", init.Result, err)
	}
	c.notify("initialized", map[string]any{})
	c.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "go", "version": 1, "text": insecure}})

	// The package-level findings come first, then the complete ones.
	early := c.diagnosticsFor(uri)
	diags := c.diagnosticsFor(uri)
	if !hasCode(early, "tls-insecure-config") {
		t.Fatalf("early diagnostics without tls-insecure-config: %+v", early)
	}
	var tlsDiag *diagnostic
	for i := range diags {
		if diags[i].Code == "tls-insecure-config" {
			tlsDiag = &diags[i]
		}
	}
	if tlsDiag == nil {
		t.Fatalf("no tls-insecure-config diagnostic in %+v", diags)
	}
	// "true" on line 6 (0-based 5) starting at byte column 41 (0-based 40).
	want := lspRange{Start: position{Line: 5, Character: 40}, End: position{Line: 5, Character: 44}}
	if tlsDiag.Range != want || tlsDiag.Severity != severityError || !strings.Contains(tlsDiag.Message, "CWE-295") {
		t.Fatalf("diagnostic = %+v", *tlsDiag)
	}

	resp := c.response(c.request("textDocument/codeAction", map[string]any{
		"textDocument": map[string]any{"uri": uri}, "range": want,
		"context": map[string]any{"diagnostics": []diagnostic{*tlsDiag}},
	}))
	var actions []codeAction
	if err := json.Unmarshal(resp.Result, &actions); err != nil {
		t.Fatal(err)
	}
	var fix, suppress *codeAction
	for i := range actions {
		switch {
		case actions[i].IsPreferred:
			fix = &actions[i]
		case strings.HasPrefix(actions[i].Title, "Suppress tls-insecure-config"):
			suppress = &actions[i]
		}
	}
	if fix == nil || suppress == nil {
		t.Fatalf("code actions = %+v", actions)
	}
	edits := fix.Edit.Changes[uri]
	if fix.Kind != "quickfix" || len(edits) != 1 || edits[0].NewText != "false" || edits[0].Range != want {
		t.Fatalf("fix = %+v", fix)
	}
	if s := suppress.Edit.Changes[uri]; len(s) != 1 || s[0].Range.Start != (position{Line: 5, Character: 45}) ||
		s[0].NewText != " //codex:ignore tls-insecure-config -- TODO: document reason" {
		t.Fatalf("suppression = %+v", suppress.Edit.Changes)
	}

	// Apply the fix and save: the diagnostics are cleared.
	if err := os.WriteFile(mainPath, []byte(strings.Replace(insecure, "true", "false", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": uri}})
	if diags := c.diagnosticsFor(uri); len(diags) != 0 {
		t.Fatalf("diagnostics after fix = %+v", diags)
	}

	if shut := c.response(c.request("shutdown", nil)); string(shut.Result) != "null" || shut.Error != nil {
		t.Fatalf("shutdown response %+v", shut)
	}
	c.notify("exit", nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not exit")
	}
}

func TestLanguageServerErrors(t *testing.T) {
	c, done := startServer(t)
	resp := c.response(c.request("workspace/symbol", map[string]any{}))
	if !strings.Contains(string(resp.Error), "-32601") {
		t.Fatalf("unknown method response %+v", resp)
	}
	c.notify("exit", nil)
	if err := <-done; err != ErrExitWithoutShutdown {
		t.Fatalf("exit without shutdown returned %v", err)
	}
}

func TestPositionConversion(t *testing.T) {
	// "é" is two bytes and one UTF-16 unit; "𝄞" is four bytes and two units.
	line := "aé𝄞b"
	for byteCol, want := range map[int]int{0: 0, 1: 0, 2: 1, 4: 2, 8: 4, 9: 5, 100: 5} {
		if got := utf16Column(line, byteCol); got != want {
			t.Errorf("utf16Column(%d) = %d, want %d", byteCol, got, want)
		}
	}
	r := issueRange([]string{"x"}, result.Location{})
	if r != (lspRange{}) {
		t.Errorf("file-level finding range = %+v", r)
	}
	r = issueRange([]string{"abc"}, result.Location{Line: 1})
	if r.End.Character != 3 {
		t.Errorf("line-level finding range = %+v", r)
	}
}

func TestURIConversion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a b", "c.go")
	got, ok := uriToPath(pathToURI(path))
	if !ok || got != path {
		t.Fatalf("round trip %q -> %q", path, got)
	}
	if _, ok := uriToPath("https://example.com/x.go"); ok {
		t.Fatal("non-file URI accepted")
	}
}

// The suppression policy is read for the project of the document, after the
// workspace is known, not for the directory the server was started in.
func TestSuppressionPolicyFollowsProject(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/lsp\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, []byte(insecure), 0o600); err != nil {
		t.Fatal(err)
	}
	var asked []string
	var mu sync.Mutex
	c, _ := startWith(t, &Server{Analyze: analyze, SuppressionsForbidden: func(root string) bool {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, root)
		return true
	}})
	uri := pathToURI(mainPath)
	c.response(c.request("initialize", map[string]any{"rootUri": pathToURI(dir), "capabilities": map[string]any{}}))
	c.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "go", "version": 1, "text": insecure}})
	if diags := c.diagnosticsFor(uri); len(diags) == 0 {
		t.Fatal("no diagnostics")
	}
	resp := c.response(c.request("textDocument/codeAction", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"range":        lspRange{Start: position{Line: 5}, End: position{Line: 5, Character: 80}},
	}))
	var actions []codeAction
	if err := json.Unmarshal(resp.Result, &actions); err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 {
		t.Fatal("the fix must still be offered")
	}
	for _, a := range actions {
		if strings.HasPrefix(a.Title, "Suppress") {
			t.Fatalf("suppression offered although the project forbids it: %+v", actions)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != dir {
		t.Fatalf("policy asked for %v, want [%s]", asked, dir)
	}
}

func hasCode(diags []diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

func codes(diags []diagnostic) []string {
	out := make([]string, len(diags))
	for i, d := range diags {
		out[i] = d.Code
	}
	return out
}

// publication is one textDocument/publishDiagnostics notification.
type publication struct {
	uri   string
	codes []string
}

func (c *client) nextPublication() publication {
	c.t.Helper()
	for {
		m := c.read()
		if m.Method != "textDocument/publishDiagnostics" {
			continue
		}
		var p publishDiagnosticsParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			c.t.Fatal(err)
		}
		if p.Diagnostics == nil {
			c.t.Fatal("diagnostics must be an array, not null")
		}
		return publication{uri: p.URI, codes: codes(p.Diagnostics)}
	}
}

func (c *client) expectPublications(want ...publication) {
	c.t.Helper()
	for i, w := range want {
		got := c.nextPublication()
		if got.uri != w.uri || strings.Join(got.codes, ",") != strings.Join(w.codes, ",") {
			c.t.Fatalf("publication %d = %+v, want %+v", i, got, w)
		}
	}
}

// twoFileModule writes a module with main.go and util.go and returns their
// paths.
func twoFileModule(t *testing.T) (dir, mainPath, utilPath string) {
	t.Helper()
	dir = t.TempDir()
	mainPath, utilPath = filepath.Join(dir, "main.go"), filepath.Join(dir, "util", "util.go")
	if err := os.MkdirAll(filepath.Dir(utilPath), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(dir, "go.mod"): "module example.test/lsp\n\ngo 1.24\n",
		mainPath:                     "package main\n\nfunc main() {}\n",
		utilPath:                     "package util\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, mainPath, utilPath
}

func finding(id, file string, line int) result.Issue {
	return result.Issue{ID: id, Severity: result.SeverityMedium, Location: result.Location{File: file, Line: line}}
}

// The package-level findings of the saved file are published before the
// analysis finishes and are replaced by its complete findings. Files outside
// the early set keep their diagnostics until then.
func TestEarlyDiagnosticsAreReplaced(t *testing.T) {
	dir, mainPath, utilPath := twoFileModule(t)
	mainURI, utilURI := pathToURI(mainPath), pathToURI(utilPath)
	type call struct {
		files   []string
		release chan struct{}
	}
	calls := make(chan call, 2)
	run := 0
	c, _ := startWith(t, &Server{Analyze: func(ctx context.Context, req Request) ([]result.Issue, error) {
		run++
		release := make(chan struct{})
		calls <- call{files: req.Files, release: release}
		if run == 1 {
			req.Early([]result.Issue{finding("pkg-rule", "main.go", 3)}, []string{"main.go"})
			<-release
			return []result.Issue{finding("pkg-rule", "main.go", 3), finding("taint-rule", "main.go", 3), finding("arch-rule", utilPath, 1)}, nil
		}
		// The package-level finding is gone; the early publication clears
		// it while util.go keeps its diagnostics.
		req.Early(nil, []string{mainPath})
		<-release
		return []result.Issue{finding("taint-rule", "main.go", 3)}, nil
	}})
	c.response(c.request("initialize", map[string]any{"rootUri": pathToURI(dir), "capabilities": map[string]any{}}))

	c.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": mainURI, "languageId": "go", "version": 1, "text": ""}})
	first := <-calls
	if len(first.files) != 1 || first.files[0] != mainPath {
		t.Fatalf("request files = %v, want [%s]", first.files, mainPath)
	}
	c.expectPublications(publication{mainURI, []string{"pkg-rule"}})
	close(first.release)
	c.expectPublications(
		publication{mainURI, []string{"pkg-rule", "taint-rule"}},
		publication{utilURI, []string{"arch-rule"}},
	)

	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": mainURI}})
	second := <-calls
	c.expectPublications(publication{mainURI, []string{}})
	close(second.release)
	c.expectPublications(
		publication{utilURI, []string{}},
		publication{mainURI, []string{"taint-rule"}},
	)
}

// A newer save cancels both phases of the analysis it supersedes, and the
// documents of the cancelled analysis are passed to the next one.
func TestNewerSaveCancelsBothPhases(t *testing.T) {
	dir, mainPath, utilPath := twoFileModule(t)
	mainURI, utilURI := pathToURI(mainPath), pathToURI(utilPath)
	started := make(chan []string, 2)
	superseded := make(chan struct{})
	run := 0
	c, _ := startWith(t, &Server{Analyze: func(ctx context.Context, req Request) ([]result.Issue, error) {
		run++
		started <- req.Files
		if run == 1 {
			// An analyzer that notices the cancellation late must not
			// publish anything.
			<-ctx.Done()
			defer close(superseded)
			req.Early([]result.Issue{finding("stale-early", "main.go", 1)}, []string{"main.go"})
			return []result.Issue{finding("stale-final", "main.go", 1)}, nil
		}
		req.Early([]result.Issue{finding("fresh-early", "util/util.go", 1)}, []string{"util/util.go"})
		return []result.Issue{finding("fresh-final", "util/util.go", 1)}, nil
	}})
	c.response(c.request("initialize", map[string]any{"rootUri": pathToURI(dir), "capabilities": map[string]any{}}))

	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": mainURI}})
	if files := <-started; len(files) != 1 || files[0] != mainPath {
		t.Fatalf("first request files = %v", files)
	}
	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": utilURI}})
	if files := <-started; len(files) != 2 || files[0] != mainPath || files[1] != utilPath {
		t.Fatalf("second request files = %v, want [%s %s]", files, mainPath, utilPath)
	}
	c.expectPublications(
		publication{utilURI, []string{"fresh-early"}},
		publication{utilURI, []string{"fresh-final"}},
	)
	<-superseded
	id := c.request("shutdown", nil)
	for {
		m := c.read()
		if m.Method == "textDocument/publishDiagnostics" {
			t.Fatalf("superseded analysis published %s", m.Params)
		}
		if m.ID != nil && *m.ID == id {
			break
		}
	}
}

// An analysis with a debounce is cancelled by a save during the wait, before
// either phase starts.
func TestDebounceMergesSaves(t *testing.T) {
	dir, mainPath, utilPath := twoFileModule(t)
	mainURI, utilURI := pathToURI(mainPath), pathToURI(utilPath)
	var mu sync.Mutex
	var requests [][]string
	c, _ := startWith(t, &Server{Debounce: 500 * time.Millisecond, Analyze: func(ctx context.Context, req Request) ([]result.Issue, error) {
		mu.Lock()
		requests = append(requests, req.Files)
		mu.Unlock()
		req.Early([]result.Issue{finding("early", "main.go", 1)}, []string{"main.go"})
		return []result.Issue{finding("final", "main.go", 1)}, nil
	}})
	c.response(c.request("initialize", map[string]any{"rootUri": pathToURI(dir), "capabilities": map[string]any{}}))
	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": mainURI}})
	c.notify("textDocument/didSave", map[string]any{"textDocument": map[string]any{"uri": utilURI}})
	c.expectPublications(
		publication{mainURI, []string{"early"}},
		publication{mainURI, []string{"final"}},
	)
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || len(requests[0]) != 2 {
		t.Fatalf("requests = %v, want one with both files", requests)
	}
}
