//go:build ignore

// Command install builds codex-cli from the current checkout into ./bin.
//
//	go run scripts/install.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	dir := filepath.Join(".", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail("prepare install directory", err)
	}
	name := "codex-cli"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(dir, name)
	pkg := "github.com/Voskan/codexsentinel/internal/version"
	ldflags := fmt.Sprintf("-s -w -X %s.Version=%s -X %s.Commit=%s -X %s.BuildDate=%s",
		pkg, gitOutput("describe", "--tags", "--always", "--dirty"), pkg, gitOutput("rev-parse", "HEAD"), pkg, time.Now().UTC().Format(time.RFC3339))
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", output, "./cmd/codex-cli")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fail("build", err)
	}
	fmt.Printf("codex-cli installed at %s\n", output)
}

func gitOutput(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", step, err)
	os.Exit(1)
}
