// Package mcp implements a Model Context Protocol server (JSON-RPC 2.0 over
// stdio) that exposes CodexSentinel's static analysis as tools: scanning a
// path or the changes since a git reference, verifying dependency
// capabilities, and explaining and listing rules. It makes no network
// requests of its own.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/jsonrpc"
	"github.com/Voskan/codexsentinel/report"
	"github.com/Voskan/codexsentinel/report/formats"
)

// SupportedProtocolVersions lists the protocol revisions the server speaks,
// newest first.
var SupportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// ScanRequest describes a scan_path or scan_diff call.
type ScanRequest struct {
	Path     string
	Severity string
	DepsOnly bool
	// GitRef limits findings to lines changed since this reference.
	GitRef string
	// ForbidNewSuppressions adds findings for suppressions added since GitRef.
	ForbidNewSuppressions bool
}

// Backend performs the analyses behind the tools.
type Backend interface {
	Scan(ctx context.Context, req ScanRequest) ([]result.Issue, error)
	// VerifyCapabilities compares dependency capabilities with the lock file
	// and returns the lock file used and any escalations.
	VerifyCapabilities(ctx context.Context, path, lockfile string) (string, []result.Issue, error)
}

// Server is a Model Context Protocol server.
type Server struct {
	Backend Backend
	Version string
	// Log receives messages about the server itself; nil discards them.
	Log io.Writer
}

// Serve handles messages from in until it is closed. Messages are
// newline-delimited JSON; Content-Length framed input is accepted too.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Backend == nil {
		return errors.New("mcp: no backend configured")
	}
	conn := jsonrpc.NewConn(in, out, jsonrpc.Lines)
	for {
		msg, err := conn.Read()
		if err != nil {
			if jsonrpc.IsParseError(err) {
				var id json.RawMessage
				if msg != nil {
					id = msg.ID
				}
				_ = conn.ReplyError(id, err.(*jsonrpc.Error))
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !msg.IsRequest() {
			continue // notifications, including notifications/initialized
		}
		res, rpcErr := s.handle(ctx, msg)
		if rpcErr != nil {
			err = conn.ReplyError(msg.ID, rpcErr)
		} else {
			err = conn.Reply(msg.ID, res)
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) handle(ctx context.Context, msg *jsonrpc.Message) (any, *jsonrpc.Error) {
	switch msg.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		version := SupportedProtocolVersions[0]
		if slices.Contains(SupportedProtocolVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "codexsentinel", "version": s.Version},
			"instructions":    "Static analysis for Go: call scan_path or scan_diff after changing Go code and fix the reported findings; explain_rule describes a rule.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolList()}, nil
	case "tools/call":
		return s.call(ctx, msg.Params)
	}
	return nil, jsonrpc.Errorf(jsonrpc.CodeMethodNotFound, "method %q is not supported", msg.Method)
}

// callResult is a CallToolResult with text content.
type callResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string, isError bool) callResult {
	return callResult{Content: []textContent{{Type: "text", Text: text}}, IsError: isError}
}

func (s *Server) call(ctx context.Context, params json.RawMessage) (any, *jsonrpc.Error) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, jsonrpc.Errorf(jsonrpc.CodeInvalidParams, "tools/call: %v", err)
	}
	t, ok := toolByName(p.Name)
	if !ok {
		return nil, jsonrpc.Errorf(jsonrpc.CodeInvalidParams, "unknown tool %q", p.Name)
	}
	args, err := decodeArgs(p.Arguments, t)
	if err != nil {
		return nil, jsonrpc.Errorf(jsonrpc.CodeInvalidParams, "%s: %v", p.Name, err)
	}
	text, err := s.run(ctx, p.Name, args)
	if err != nil {
		if s.Log != nil {
			fmt.Fprintf(s.Log, "codexsentinel mcp: %s failed: %v\n", p.Name, err)
		}
		return textResult(err.Error(), true), nil
	}
	return textResult(text, false), nil
}

func (s *Server) run(ctx context.Context, name string, a arguments) (string, error) {
	switch name {
	case "scan_path":
		issues, err := s.Backend.Scan(ctx, ScanRequest{Path: a.Path, Severity: a.Severity, DepsOnly: a.DepsOnly})
		return agentReport(issues), err
	case "scan_diff":
		issues, err := s.Backend.Scan(ctx, ScanRequest{Path: a.Path, GitRef: a.GitRef, ForbidNewSuppressions: a.ForbidNewSuppressions})
		return agentReport(issues), err
	case "verify_capabilities":
		lockfile, issues, err := s.Backend.VerifyCapabilities(ctx, a.Path, a.Lockfile)
		if err != nil {
			return "", err
		}
		if len(issues) == 0 {
			return "STATUS: PASS (no capability escalations against " + lockfile + ")\n", nil
		}
		return agentReport(issues), nil
	case "explain_rule":
		doc, ok := catalog.Lookup(a.Rule)
		if !ok {
			return "", catalog.UnknownRuleError(a.Rule)
		}
		var b bytes.Buffer
		catalog.WriteCard(&b, doc)
		return b.String(), nil
	case "list_rules":
		docs, err := catalog.Filter(a.Category, "")
		if err != nil {
			return "", err
		}
		var b bytes.Buffer
		err = catalog.WriteTable(&b, docs)
		return b.String(), err
	}
	return "", fmt.Errorf("tool %q is not implemented", name)
}

func agentReport(issues []result.Issue) string {
	return formats.AgentReport(report.FromResults(issues))
}

// arguments holds the union of all tool arguments; decodeArgs checks that
// only the tool's own properties are present.
type arguments struct {
	Path                  string `json:"path"`
	Severity              string `json:"severity"`
	DepsOnly              bool   `json:"deps_only"`
	GitRef                string `json:"git_ref"`
	ForbidNewSuppressions bool   `json:"forbid_new_suppressions"`
	Lockfile              string `json:"lockfile"`
	Rule                  string `json:"rule"`
	Category              string `json:"category"`
}

func decodeArgs(raw json.RawMessage, t tool) (arguments, error) {
	var a arguments
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return a, fmt.Errorf("arguments must be an object: %v", err)
	}
	for name := range fields {
		if _, ok := t.properties[name]; !ok {
			return a, fmt.Errorf("unknown argument %q", name)
		}
	}
	for _, name := range t.required {
		if v, ok := fields[name]; !ok || string(v) == `""` || string(v) == "null" {
			return a, fmt.Errorf("missing required argument %q", name)
		}
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, fmt.Errorf("invalid arguments: %v", err)
	}
	if a.Severity != "" && result.ParseSeverity(a.Severity) == result.SeverityUnknown {
		return a, fmt.Errorf("unknown severity %q", a.Severity)
	}
	if strings.HasPrefix(a.GitRef, "-") {
		return a, fmt.Errorf("invalid git_ref %q", a.GitRef)
	}
	return a, nil
}
