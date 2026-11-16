package codex

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/internal/git"
)

func gitRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-q", "-m", "init"}} {
		cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestScanForbidsNewSuppressions(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(git.AllowSuppressionsEnv, "")
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	gitRepo(t, dir)
	// The directive names the guardrail's own rule; it must not hide itself.
	src := "package main\n\nfunc main() {\n\t_ = 1 //codex:ignore unauthorized-suppression-added -- try\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.json")
	err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--forbid-new-suppressions", "--diff", "HEAD")
	var found *IssuesFoundError
	if !errors.As(err, &found) {
		t.Fatalf("scan did not fail on the new suppression: %v", err)
	}
	var guard []string
	for _, is := range reportIssues(t, out) {
		if is.RuleID == git.SuppressionRuleID {
			guard = append(guard, string(is.Severity)+" "+is.File+":"+strconv.Itoa(is.Line))
		}
	}
	if strings.Join(guard, ",") != "CRITICAL main.go:4" {
		t.Fatalf("guardrail findings = %v", guard)
	}

	// Without the flag the directive is an ordinary inline ignore.
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--diff", "HEAD"); err != nil {
		t.Fatalf("scan without the policy: %v", err)
	}

	// An approved change passes.
	t.Setenv(git.AllowSuppressionsEnv, "1")
	if err := runCLI(t, "scan", dir, "--format", "json", "--out", out, "--forbid-new-suppressions"); err != nil {
		t.Fatalf("approved suppression rejected: %v", err)
	}
}

func TestScanAgentFormatToStdout(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := fixture(t, "package main\n\nfunc main() {}\n")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	runErr := runCLI(t, "scan", dir, "--format", "agent", "--out", "-")
	os.Stdout = stdout
	w.Close()
	data, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatal(runErr)
	}
	if string(data) != "STATUS: PASS (0 issues)\n" {
		t.Fatalf("stdout = %q", data)
	}
	if got := defaultOutputPath("agent"); got != "codex-report.agent.txt" {
		t.Fatalf("default output path = %q", got)
	}
}
