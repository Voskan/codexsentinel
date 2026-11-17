package workspace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// WorkFile returns the go.work file that governs dir, as the go command
// selects it (including the GOWORK environment variable), or "" when dir is
// not in a workspace or workspaces are disabled with GOWORK=off.
func WorkFile(dir string) string {
	cmd := exec.Command("go", "env", "GOWORK")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if path == "" || path == "off" {
		return ""
	}
	return path
}

// WorkModule is a module used by a go.work file.
type WorkModule struct {
	Path  string // module path from its go.mod
	GoMod string // absolute path of its go.mod
}

// WorkModules returns the modules a go.work file uses, in directory order.
// Use directives whose directory has no go.mod are skipped, as the go command
// reports them itself.
func WorkModules(workFile string) ([]WorkModule, error) {
	data, err := os.ReadFile(workFile)
	if err != nil {
		return nil, err
	}
	wf, err := modfile.ParseWork(workFile, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", workFile, err)
	}
	var out []WorkModule
	for _, use := range wf.Use {
		dir := filepath.FromSlash(use.Path)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(workFile), dir)
		}
		gomod := filepath.Join(dir, "go.mod")
		content, err := os.ReadFile(gomod)
		if err != nil {
			continue
		}
		path := modfile.ModulePath(content)
		if path == "" {
			continue
		}
		out = append(out, WorkModule{Path: path, GoMod: filepath.Clean(gomod)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GoMod < out[j].GoMod })
	return out, nil
}

// WorkspaceModulePaths returns the module paths of the go.work workspace
// that governs dir, or nil outside a workspace. Requirements on these
// modules are satisfied by their directories, not by downloaded versions.
func WorkspaceModulePaths(dir string) map[string]bool {
	work := WorkFile(dir)
	if work == "" {
		return nil
	}
	mods, err := WorkModules(work)
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(mods))
	for _, m := range mods {
		out[m.Path] = true
	}
	return out
}

// findWorkRoot returns the go.work file governing dir when dir is not inside
// a module of its own, with the used modules below target.
func findWorkRoot(dir, target string) (string, []WorkModule, error) {
	work := WorkFile(dir)
	if work == "" {
		return "", nil, nil
	}
	mods, err := WorkModules(work)
	if err != nil {
		return "", nil, err
	}
	var inside []WorkModule
	for _, m := range mods {
		if within(target, filepath.Dir(m.GoMod)) {
			inside = append(inside, m)
		}
	}
	return work, inside, nil
}

// GoModFiles returns the project root of target and the go.mod files of the
// modules it covers: the module containing target, or, for a directory of a
// go.work workspace outside any module, the workspace modules below it.
func GoModFiles(target string) (string, []string, error) {
	root, err := ProjectRoot(target)
	if err != nil {
		return "", nil, err
	}
	if mod := filepath.Join(root, "go.mod"); fileExists(mod) {
		return root, []string{mod}, nil
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", nil, err
	}
	_, mods, err := findWorkRoot(root, abs)
	if err != nil {
		return "", nil, err
	}
	var out []string
	for _, m := range mods {
		out = append(out, m.GoMod)
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("no go.mod found for %s", target)
	}
	return root, out, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
