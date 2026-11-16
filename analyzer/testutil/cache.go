package testutil

import (
	"fmt"
	"os"
	"testing"
)

// cacheDirEnv mirrors cache.EnvDir; testutil does not import the cache package.
const cacheDirEnv = "CODEXSENTINEL_CACHE_DIR"

// RunIsolated runs the tests of m with the analysis cache in a temporary
// directory instead of the user cache directory, and removes it afterwards.
// Use it from TestMain in packages whose tests run full scans:
//
//	func TestMain(m *testing.M) { os.Exit(testutil.RunIsolated(m)) }
func RunIsolated(m *testing.M) int {
	dir, err := os.MkdirTemp("", "codexsentinel-cache-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	if err := os.Setenv(cacheDirEnv, dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}
