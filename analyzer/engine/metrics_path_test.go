package engine

import (
	"path/filepath"
	"testing"
)

func TestGetDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	for input, want := range map[string]string{dir: dir, filepath.Join(dir, "main.go"): dir, "": "."} {
		if got := getDirectoryPath(input); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}
