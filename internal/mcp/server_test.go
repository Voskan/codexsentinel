package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
)

// engineBackend runs the analysis engine directly.
type engineBackend struct{}

func (engineBackend) Scan(ctx context.Context, req ScanRequest) ([]result.Issue, error) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	return engine.Run(ctx, req.Path, &cfg)
}

func (engineBackend) VerifyCapabilities(context.Context, string, string) (string, []result.Issue, error) {
	return ".codexsentinel.caps.json", nil, nil
}

type rpcClient struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *rpcClient) write(v any) {
	c.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.in.Write(append(data, '\n')); err != nil {
		c.t.Fatal(err)
	}
}

// call sends a request and returns its response, which must be the next
// line on the stream.
func (c *rpcClient) call(method string, params any) rpcResponse {
	c.t.Helper()
	c.id++
	c.write(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	line, err := c.out.ReadString('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	var resp rpcResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		c.t.Fatalf("stream contains a non-JSON line: %q", line)
	}
	if resp.ID != c.id {
		c.t.Fatalf("response id %d, want %d: %s", resp.ID, c.id, line)
	}
	return resp
}

func startMCP(t *testing.T) (*rpcClient, chan error) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := &Server{Backend: engineBackend{}, Version: "test"}
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	return &rpcClient{t: t, in: inW, out: bufio.NewReader(outR)}, done
}

func toolText(t *testing.T, resp rpcResponse) (string, bool) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("error response: %+v", resp.Error)
	}
	var r callResult
	if err := json.Unmarshal(resp.Result, &r); err != nil || len(r.Content) != 1 || r.Content[0].Type != "text" {
		t.Fatalf("result %s (%v)", resp.Result, err)
	}
	return r.Content[0].Text, r.IsError
}

func TestModelContextProtocolSession(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.test/mcp\n\ngo 1.24\n",
		"main.go": "package main\n\nimport \"crypto/tls\"\n\nfunc main() {\n\t_ = &tls.Config{InsecureSkipVerify: true}\n}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, done := startMCP(t)

	init := c.call("initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	var info struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct{ Name, Version string }
	}
	if err := json.Unmarshal(init.Result, &info); err != nil || info.ProtocolVersion != "2025-03-26" || info.Capabilities["tools"] == nil || info.ServerInfo.Name != "codexsentinel" {
		t.Fatalf("initialize: %s (%v)", init.Result, err)
	}
	c.write(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if ping := c.call("ping", nil); string(ping.Result) != "{}" {
		t.Fatalf("ping: %s", ping.Result)
	}

	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema struct {
				Type       string                    `json:"type"`
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(c.call("tools/list", nil).Result, &list); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
		if tl.InputSchema.Type != "object" || tl.Description == "" {
			t.Errorf("tool %s has schema %+v", tl.Name, tl.InputSchema)
		}
		for _, req := range tl.InputSchema.Required {
			if _, ok := tl.InputSchema.Properties[req]; !ok {
				t.Errorf("tool %s requires undeclared %s", tl.Name, req)
			}
		}
	}
	if strings.Join(names, ",") != "scan_path,scan_diff,verify_capabilities,explain_rule,list_rules" {
		t.Fatalf("tools = %v", names)
	}

	text, isErr := toolText(t, c.call("tools/call", map[string]any{"name": "explain_rule", "arguments": map[string]any{"rule": "sql-injection"}}))
	if isErr || !strings.Contains(text, "CWE-89") || !strings.Contains(text, "Vulnerable example") {
		t.Fatalf("explain_rule: %q", text)
	}
	text, isErr = toolText(t, c.call("tools/call", map[string]any{"name": "scan_path", "arguments": map[string]any{"path": dir}}))
	if isErr || !strings.HasPrefix(text, "STATUS: FAIL") || !strings.Contains(text, "tls-insecure-config") || !strings.Contains(text, "PATCH: replace 6:38-6:42 with `false`") {
		t.Fatalf("scan_path: %q", text)
	}
	text, isErr = toolText(t, c.call("tools/call", map[string]any{"name": "list_rules", "arguments": map[string]any{"category": "reliability"}}))
	if isErr || !strings.Contains(text, "defer-in-loop") || strings.Contains(text, "sql-injection") {
		t.Fatalf("list_rules: %q", text)
	}
	text, isErr = toolText(t, c.call("tools/call", map[string]any{"name": "explain_rule", "arguments": map[string]any{"rule": "sql-injektion"}}))
	if !isErr || !strings.Contains(text, "sql-injection") {
		t.Fatalf("unknown rule: %q (isError %v)", text, isErr)
	}

	for _, bad := range []map[string]any{
		{"name": "no_such_tool"},
		{"name": "scan_path", "arguments": map[string]any{}},
		{"name": "scan_path", "arguments": map[string]any{"path": dir, "extra": 1}},
		{"name": "scan_path", "arguments": map[string]any{"path": dir, "severity": "urgent"}},
	} {
		if resp := c.call("tools/call", bad); resp.Error == nil || resp.Error.Code != -32602 {
			t.Errorf("tools/call %v: %+v", bad, resp)
		}
	}
	if resp := c.call("resources/list", nil); resp.Error == nil || resp.Error.Code != -32601 {
		t.Errorf("unknown method: %+v", resp)
	}

	c.in.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestModelContextProtocolHeaderFraming(t *testing.T) {
	c, done := startMCP(t)
	body := `{"jsonrpc":"2.0","id":7,"method":"ping"}`
	if _, err := io.WriteString(c.in, "Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body); err != nil {
		t.Fatal(err)
	}
	header, _ := c.out.ReadString('\n')
	if !strings.HasPrefix(header, "Content-Length:") {
		t.Fatalf("reply not framed like the request: %q", header)
	}
	c.in.Close()
	<-done
}
