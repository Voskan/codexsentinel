// Package lsp implements a Language Server Protocol server over stdio that
// publishes CodexSentinel findings as diagnostics and offers their fixes and
// suppressions as code actions. Analysis runs when a document is opened or
// saved; edits that are not saved are not analyzed.
package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/jsonrpc"
)

// Analyzer analyzes the module at root and returns findings whose file paths
// are relative to root or absolute.
type Analyzer func(ctx context.Context, root string) ([]result.Issue, error)

// ErrExitWithoutShutdown is returned when the client sends exit before
// shutdown, which the protocol defines as an abnormal termination.
var ErrExitWithoutShutdown = errors.New("exit received before shutdown")

// Server is a Language Server Protocol server.
type Server struct {
	// Analyze runs the analysis; it is required.
	Analyze Analyzer
	// Log receives diagnostics about the server itself. It must not be the
	// protocol output. Nil discards them.
	Log io.Writer
	// Debounce delays an analysis so that rapid saves start only one.
	Debounce time.Duration
	// ForbidSuppressions hides the code action that adds a suppression
	// comment, for projects that reject new suppressions.
	ForbidSuppressions bool

	conn      *jsonrpc.Conn
	mu        sync.Mutex
	root      string
	issues    map[string][]result.Issue // absolute path -> findings
	published map[string]bool           // URIs with published diagnostics
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	shutdown  bool
}

// Serve reads requests from in and writes responses to out until the client
// sends exit or in is closed.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Analyze == nil {
		return errors.New("lsp: no analyzer configured")
	}
	s.conn = jsonrpc.NewConn(in, out, jsonrpc.Headers)
	s.issues, s.published = map[string][]result.Issue{}, map[string]bool{}
	ctx, stop := context.WithCancel(ctx)
	defer func() {
		stop()
		s.wg.Wait()
	}()
	for {
		msg, err := s.conn.Read()
		if err != nil {
			if jsonrpc.IsParseError(err) {
				_ = s.conn.ReplyError(idOf(msg), err.(*jsonrpc.Error))
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msg.Method == "exit" {
			if s.isShutdown() {
				return nil
			}
			return ErrExitWithoutShutdown
		}
		if err := s.dispatch(ctx, msg); err != nil {
			return err
		}
	}
}

func idOf(msg *jsonrpc.Message) json.RawMessage {
	if msg == nil {
		return nil
	}
	return msg.ID
}

func (s *Server) isShutdown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdown
}

func (s *Server) dispatch(ctx context.Context, msg *jsonrpc.Message) error {
	var result any
	var rpcErr *jsonrpc.Error
	switch msg.Method {
	case "initialize":
		result, rpcErr = s.initialize(msg.Params)
	case "initialized", "$/cancelRequest", "$/setTrace", "textDocument/didChange", "textDocument/didClose", "workspace/didChangeConfiguration":
	case "textDocument/didOpen", "textDocument/didSave":
		s.documentChanged(ctx, msg.Params)
	case "textDocument/codeAction":
		result, rpcErr = s.codeActions(msg.Params)
	case "shutdown":
		s.mu.Lock()
		s.shutdown = true
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Unlock()
	default:
		if msg.IsRequest() {
			rpcErr = jsonrpc.Errorf(jsonrpc.CodeMethodNotFound, "method %q is not supported", msg.Method)
		}
	}
	if !msg.IsRequest() {
		return nil
	}
	if rpcErr != nil {
		return s.conn.ReplyError(msg.ID, rpcErr)
	}
	if result == nil {
		return s.conn.Reply(msg.ID, nil)
	}
	return s.conn.Reply(msg.ID, result)
}

func (s *Server) initialize(params json.RawMessage) (any, *jsonrpc.Error) {
	var p initializeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, jsonrpc.Errorf(jsonrpc.CodeInvalidParams, "initialize: %v", err)
	}
	root := p.RootPath
	for _, uri := range append([]string{p.RootURI}, folderURIs(p)...) {
		if path, ok := uriToPath(uri); ok {
			root = path
			break
		}
	}
	if root != "" {
		abs, err := filepath.Abs(root)
		if err == nil {
			root = abs
		}
	}
	s.mu.Lock()
	s.root = root
	s.mu.Unlock()
	return map[string]any{
		"capabilities": map[string]any{
			"textDocumentSync":   map[string]any{"openClose": true, "change": 0, "save": map[string]any{"includeText": false}},
			"codeActionProvider": map[string]any{"codeActionKinds": []string{"quickfix"}},
		},
		"serverInfo": map[string]any{"name": "codexsentinel"},
	}, nil
}

func folderURIs(p initializeParams) []string {
	uris := make([]string, len(p.WorkspaceFolders))
	for i, f := range p.WorkspaceFolders {
		uris[i] = f.URI
	}
	return uris
}

// documentChanged schedules an analysis, cancelling one that is still
// running or waiting.
func (s *Server) documentChanged(ctx context.Context, params json.RawMessage) {
	var p documentParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.logf("ignoring document notification: %v", err)
		return
	}
	path, ok := uriToPath(p.TextDocument.URI)
	if !ok || !strings.HasSuffix(path, ".go") && filepath.Base(path) != "go.mod" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		return
	}
	root := s.root
	if root == "" || !within(root, path) {
		root = moduleRoot(filepath.Dir(path))
	}
	if s.cancel != nil {
		s.cancel()
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.run(runCtx, root)
	}()
}

func (s *Server) run(ctx context.Context, root string) {
	if s.Debounce > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.Debounce):
		}
	}
	start := time.Now()
	issues, err := s.Analyze(ctx, root)
	if ctx.Err() != nil {
		return // superseded by a newer analysis
	}
	if err != nil {
		s.logf("analysis of %s failed: %v", root, err)
		return
	}
	s.logf("analyzed %s in %s: %d findings", root, time.Since(start).Round(time.Millisecond), len(issues))
	s.publish(ctx, root, issues)
}

// publish sends diagnostics for every file with findings and empty
// diagnostics for files whose findings are gone.
func (s *Server) publish(ctx context.Context, root string, issues []result.Issue) {
	byFile := map[string][]result.Issue{}
	for _, is := range issues {
		if is.Location.File == "" {
			continue
		}
		is = absolute(root, is)
		byFile[is.Location.File] = append(byFile[is.Location.File], is)
	}
	s.mu.Lock()
	if ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	var stale []string
	for uri := range s.published {
		if path, _ := uriToPath(uri); within(root, path) && byFile[path] == nil {
			stale = append(stale, uri)
			delete(s.published, uri)
		}
	}
	for path := range s.issues {
		if within(root, path) {
			delete(s.issues, path)
		}
	}
	for path, list := range byFile {
		s.issues[path] = list
		s.published[pathToURI(path)] = true
	}
	s.mu.Unlock()

	sort.Strings(stale)
	for _, uri := range stale {
		s.notifyDiagnostics(uri, []diagnostic{})
	}
	paths := make([]string, 0, len(byFile))
	for path := range byFile {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		s.notifyDiagnostics(pathToURI(path), diagnosticsFor(path, byFile[path]))
	}
}

func (s *Server) notifyDiagnostics(uri string, diags []diagnostic) {
	if err := s.conn.Notify("textDocument/publishDiagnostics", publishDiagnosticsParams{URI: uri, Diagnostics: diags}); err != nil {
		s.logf("publish diagnostics: %v", err)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		fmt.Fprintf(s.Log, "codexsentinel lsp: "+format+"\n", args...)
	}
}

// absolute returns a copy of the finding whose location, trace and fix paths
// are absolute.
func absolute(root string, is result.Issue) result.Issue {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(root, filepath.FromSlash(p))
	}
	is.Location.File = abs(is.Location.File)
	is.Trace = append([]result.TraceStep(nil), is.Trace...)
	for i := range is.Trace {
		is.Trace[i].Location.File = abs(is.Trace[i].Location.File)
	}
	if is.Fix != nil {
		fix := *is.Fix
		fix.Edits = append([]result.TextEdit(nil), fix.Edits...)
		for i := range fix.Edits {
			fix.Edits[i].File = abs(fix.Edits[i].File)
		}
		is.Fix = &fix
	}
	return is
}

// within reports whether path is root or below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// moduleRoot returns the nearest directory at or above dir containing go.mod,
// or dir itself.
func moduleRoot(dir string) string {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir
		}
		d = parent
	}
}
