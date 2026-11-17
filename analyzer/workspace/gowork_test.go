package workspace

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Voskan/codexsentinel/config"
)

func goWorkspace(t *testing.T) string {
	t.Helper()
	t.Setenv("GOWORK", "")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, "go.work", "go 1.24\n\nuse (\n\t./svc/api\n\t./lib\n)\n")
	write(t, dir, "lib/go.mod", "module example.test/lib\n\ngo 1.24\n")
	write(t, dir, "lib/lib.go", "package lib\n\nfunc Name() string { return \"lib\" }\n")
	write(t, dir, "svc/api/go.mod", "module example.test/api\n\ngo 1.24\n\nrequire example.test/lib v0.0.0\n")
	write(t, dir, "svc/api/main.go", "package main\n\nimport \"example.test/lib\"\n\nfunc main() { println(lib.Name()) }\n")
	write(t, dir, "tools/gen.go", "package tools\n")
	return dir
}

func TestWorkModules(t *testing.T) {
	dir := goWorkspace(t)
	if got := WorkFile(dir); got != filepath.Join(dir, "go.work") {
		t.Fatalf("WorkFile = %q", got)
	}
	// Use directives without a go.mod are left to the go command to report.
	other := write(t, dir, "other.work", "go 1.24\n\nuse (\n\t./svc/api\n\t./lib\n\t./missing\n)\n")
	mods, err := WorkModules(other)
	if err != nil {
		t.Fatal(err)
	}
	want := []WorkModule{
		{Path: "example.test/lib", GoMod: filepath.Join(dir, "lib", "go.mod")},
		{Path: "example.test/api", GoMod: filepath.Join(dir, "svc", "api", "go.mod")},
	}
	if !slices.Equal(mods, want) {
		t.Fatalf("WorkModules = %+v, want %+v", mods, want)
	}
	if paths := WorkspaceModulePaths(filepath.Join(dir, "svc", "api")); !paths["example.test/lib"] || !paths["example.test/api"] || len(paths) != 2 {
		t.Fatalf("WorkspaceModulePaths = %v", paths)
	}
}

func TestWorkspacesCanBeDisabled(t *testing.T) {
	dir := goWorkspace(t)
	t.Setenv("GOWORK", "off")
	if got := WorkFile(dir); got != "" {
		t.Fatalf("WorkFile with GOWORK=off = %q", got)
	}
	if _, _, err := GoModFiles(dir); err == nil {
		t.Fatal("GoModFiles found modules with workspaces disabled")
	}
}

func TestGoModFiles(t *testing.T) {
	dir := goWorkspace(t)
	for _, tc := range []struct {
		target string
		root   string
		mods   []string
	}{
		{dir, dir, []string{"lib/go.mod", "svc/api/go.mod"}},
		{filepath.Join(dir, "svc"), dir, []string{"svc/api/go.mod"}},
		{filepath.Join(dir, "svc", "api"), filepath.Join(dir, "svc", "api"), []string{"svc/api/go.mod"}},
		{filepath.Join(dir, "lib", "lib.go"), filepath.Join(dir, "lib"), []string{"lib/go.mod"}},
	} {
		root, mods, err := GoModFiles(tc.target)
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		var rel []string
		for _, m := range mods {
			r, _ := filepath.Rel(dir, m)
			rel = append(rel, filepath.ToSlash(r))
		}
		if root != tc.root || !slices.Equal(rel, tc.mods) {
			t.Errorf("GoModFiles(%s) = %s %v, want %s %v", tc.target, root, rel, tc.root, tc.mods)
		}
	}
	if _, _, err := GoModFiles(filepath.Join(dir, "tools")); err == nil {
		t.Error("GoModFiles accepted a workspace directory without modules")
	}
}

func TestLoadGoWorkspaceRoot(t *testing.T) {
	dir := goWorkspace(t)
	cfg := config.NewDefaultConfig()
	ws, err := Load(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ws.RootDir != dir || ws.GoModPath != "" || len(ws.GoModPaths) != 2 {
		t.Fatalf("root %q, go.mod %q, modules %v", ws.RootDir, ws.GoModPath, ws.GoModPaths)
	}
	var pkgs []string
	for _, pkg := range ws.Packages {
		pkgs = append(pkgs, pkg.PkgPath)
	}
	slices.Sort(pkgs)
	if !slices.Equal(pkgs, []string{"example.test/api", "example.test/lib"}) {
		t.Fatalf("packages = %v", pkgs)
	}
	if root, err := ProjectRoot(filepath.Join(dir, "svc")); err != nil || root != dir {
		t.Fatalf("ProjectRoot(svc) = %q, %v", root, err)
	}
}
