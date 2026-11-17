package codex

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionDefinition(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Name   string `yaml:"name"`
		Inputs map[string]struct {
			Default *string `yaml:"default"`
		} `yaml:"inputs"`
		Runs struct {
			Using string `yaml:"using"`
			Steps []struct {
				Shell string            `yaml:"shell"`
				Run   string            `yaml:"run"`
				Env   map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	if action.Name == "" || action.Runs.Using != "composite" || len(action.Runs.Steps) == 0 {
		t.Fatalf("action = %+v", action)
	}
	for _, in := range []string{"version", "path", "severity", "diff", "strict", "forbid-new-suppressions", "caps-verify", "format", "args"} {
		if input, ok := action.Inputs[in]; !ok || input.Default == nil {
			t.Errorf("input %q missing or without default", in)
		}
	}
	bash, bashErr := exec.LookPath("bash")
	for i, step := range action.Runs.Steps {
		if step.Shell != "bash" {
			t.Errorf("step %d: shell %q", i, step.Shell)
		}
		// Inputs reach the scripts through the environment only, so that
		// input values cannot inject shell code.
		if strings.Contains(step.Run, "${{") {
			t.Errorf("step %d interpolates expressions into its script", i)
		}
		if bashErr != nil {
			continue
		}
		script := filepath.Join(t.TempDir(), "step.sh")
		if err := os.WriteFile(script, []byte(step.Run), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", script).CombinedOutput(); err != nil {
			t.Errorf("step %d is not valid bash: %v\n%s", i, err, out)
		}
	}
}

func TestPreCommitHooks(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks []struct {
		ID            string `yaml:"id"`
		Name          string `yaml:"name"`
		Entry         string `yaml:"entry"`
		Language      string `yaml:"language"`
		PassFilenames *bool  `yaml:"pass_filenames"`
	}
	if err := yaml.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"codexsentinel-scan": "codex-cli scan . --strict --severity high",
		"codexsentinel-caps": "codex-cli caps verify .",
	}
	if len(hooks) != len(want) {
		t.Fatalf("hooks = %+v", hooks)
	}
	for _, h := range hooks {
		if want[h.ID] != h.Entry || h.Language != "golang" || h.Name == "" || h.PassFilenames == nil || *h.PassFilenames {
			t.Errorf("hook %+v", h)
		}
	}
}

func TestActionScanStepArguments(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, s := range action.Runs.Steps {
		if s.Name == "Run codex-cli scan" {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatal("scan step not found")
	}
	// A stand-in codex-cli records its arguments.
	bin, work := t.TempDir(), t.TempDir()
	logFile := filepath.Join(work, "calls.log")
	fake := "#!/bin/sh\necho \"$*\" >> \"$CALLS\"\n"
	if err := os.WriteFile(filepath.Join(bin, "codex-cli"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".codexsentinel.caps.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) string {
		_ = os.Remove(logFile)
		cmd := exec.Command(bash, "-c", script)
		cmd.Dir = work
		cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "CALLS=" + logFile,
			"INPUT_PATH=.", "INPUT_SEVERITY=medium", "INPUT_DIFF=", "INPUT_STRICT=true", "INPUT_FORBID=false",
			"INPUT_CAPS_VERIFY=true", "INPUT_FORMAT=github", "INPUT_OUTPUT=", "INPUT_ARGS="}, env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("scan step: %v\n%s", err, out)
		}
		calls, _ := os.ReadFile(logFile)
		return string(calls)
	}
	if got := run(); got != "scan . --format github --severity medium --strict\ncaps verify .\n" {
		t.Errorf("default calls:\n%s", got)
	}
	got := run("INPUT_DIFF=origin/main", "INPUT_FORBID=true", "INPUT_CAPS_VERIFY=false", "INPUT_ARGS=--no-cache  --config ci.yaml")
	if got != "scan . --format github --severity medium --diff origin/main --strict --forbid-new-suppressions --no-cache --config ci.yaml\n" {
		t.Errorf("calls with options:\n%s", got)
	}
}

func TestScanGitHubFormat(t *testing.T) {
	t.Chdir(t.TempDir())
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	dir := fixture(t, "package main\n\nimport \"crypto/tls\"\n\nfunc main() {\n\t_ = &tls.Config{InsecureSkipVerify: true}\n}\n")
	out := runStdio(t, "", "scan", dir, "--format", "github")
	if !strings.HasPrefix(out, "::error file=main.go,line=6,col=38,") || strings.Contains(out, "Analysis complete") {
		t.Fatalf("stdout must hold only workflow commands:\n%s", out)
	}
	data, err := os.ReadFile(summary)
	if err != nil || !strings.Contains(string(data), "`tls-insecure-config`") {
		t.Fatalf("summary %q (%v)", data, err)
	}

	report := filepath.Join(t.TempDir(), "gl.json")
	if err := runCLI(t, "scan", dir, "--format", "gitlab", "--out", report); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(report); !strings.Contains(string(data), `"check_name": "tls-insecure-config"`) {
		t.Fatalf("gitlab report:\n%s", data)
	}
}
