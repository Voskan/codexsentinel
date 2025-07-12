package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// installDir defines where the binary should be installed
var installDir = filepath.Join(".", "bin")

func main() {
	fmt.Println("🔧 Installing CodexSentinel...")

	if err := ensureInstallDir(); err != nil {
		exitWithError("failed to prepare install directory", err)
	}

	output := filepath.Join(installDir, binaryName("codex"))
	cmd := exec.Command("go", "build", "-o", output, "./cmd/codex-cli")
	cmd.Env = os.Environ()

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		exitWithError("build failed", err)
	}

	fmt.Printf("✅ CodexSentinel installed at: %s\n", output)
}

func ensureInstallDir() error {
	if _, err := os.Stat(installDir); os.IsNotExist(err) {
		return os.MkdirAll(installDir, 0o755)
	}
	return nil
}

func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func exitWithError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "❌ %s: %v\n", msg, err)
	os.Exit(1)
}
