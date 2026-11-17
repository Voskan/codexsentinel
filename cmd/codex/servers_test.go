package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/internal/git"
)

// runStdio runs a command with the given stdin and returns its stdout.
func runStdio(t *testing.T, input string, args ...string) string {
	t.Helper()
	inFile := filepath.Join(t.TempDir(), "in")
	outFile := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(inFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(inFile)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	stdin, stdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = in, out
	runErr := runCLI(t, args...)
	os.Stdin, os.Stdout = stdin, stdout
	out.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMCPCommandScanDiff(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(git.AllowSuppressionsEnv, "")
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	gitRepo(t, dir)
	src := "package main\n\nfunc main() {\n\t_ = 1 //nolint:gosec\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	call := func(id int, method string, params any) string {
		data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		return string(data) + "\n"
	}
	input := call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18"}) +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		call(2, "tools/call", map[string]any{"name": "scan_diff", "arguments": map[string]any{"path": dir, "git_ref": "HEAD", "forbid_new_suppressions": true}})
	out := runStdio(t, input, "mcp")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want two responses on stdout, got %q", out)
	}
	var resp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil || len(resp.Result.Content) != 1 {
		t.Fatalf("scan_diff response %q (%v)", lines[1], err)
	}
	if text := resp.Result.Content[0].Text; !strings.Contains(text, "ISSUE [CRITICAL] unauthorized-suppression-added (CWE-693) at main.go:4") {
		t.Fatalf("scan_diff text:\n%s", text)
	}
}

func TestLSPCommandShutdown(t *testing.T) {
	frame := func(body string) string { return "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body }
	input := frame(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`) +
		frame(`{"jsonrpc":"2.0","id":2,"method":"shutdown"}`) +
		frame(`{"jsonrpc":"2.0","method":"exit"}`)
	out := runStdio(t, input, "lsp")
	if !strings.HasPrefix(out, "Content-Length: ") || !strings.Contains(out, `"id":2,"result":null`) {
		t.Fatalf("stdout = %q", out)
	}
}
