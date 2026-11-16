package codex

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capsModule(t *testing.T, formatter string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                 "module example.com/app\n\ngo 1.24\n\nrequire example.com/formatter v0.0.0\n\nreplace example.com/formatter => ./formatter\n",
		"formatter/go.mod":       "module example.com/formatter\n\ngo 1.24\n",
		"formatter/formatter.go": formatter,
		"main.go":                "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/formatter\"\n)\n\nfunc main() { fmt.Println(formatter.Format(\"x\")) }\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runCaps(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCmd(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(append([]string{"caps"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func TestCapsLockAndVerify(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := capsModule(t, "package formatter\n\nimport \"strings\"\n\nfunc Format(s string) string { return strings.ToUpper(s) }\n")
	if _, err := runCaps(t, "lock", dir); err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join(dir, ".codexsentinel.caps.json"))
	if err != nil || !strings.Contains(string(lock), `"example.com/formatter": []`) {
		t.Fatalf("unexpected lock file: %s, %v", lock, err)
	}
	if out, err := runCaps(t, "verify", dir); err != nil || !strings.Contains(out, "No capability escalations") {
		t.Fatalf("verify on unchanged module: %q, %v", out, err)
	}

	src := "package formatter\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nfunc Format(s string) string {\n\t_ = exec.Command(\"id\").Run()\n\treturn strings.ToUpper(s)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "formatter", "formatter.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCaps(t, "inspect", dir)
	if err != nil || !strings.Contains(out, "CAP_EXEC") {
		t.Fatalf("inspect: %q, %v", out, err)
	}
	out, err = runCaps(t, "verify", dir)
	var issuesErr *IssuesFoundError
	if !errors.As(err, &issuesErr) || !strings.Contains(out, "[CRITICAL]") || !strings.Contains(out, "example.com/formatter.Format -> os/exec.") {
		t.Fatalf("verify after escalation: %q, %v", out, err)
	}
}
