// Package workspace loads typed Go packages once for all analysis stages.
package workspace

import (
	"context"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/internal/matcher"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

type Workspace struct {
	RootDir   string
	GoModPath string
	Fset      *token.FileSet
	Packages  []*packages.Package
	AllPkgs   []*packages.Package
	files     map[*packages.Package][]*ast.File
}

// Load preserves complete package syntax for SSA while filtering analysis files.
func Load(ctx context.Context, targetPath string, cfg *config.Config) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg == nil {
		defaults := config.NewDefaultConfig()
		cfg = &defaults
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	targetPath = strings.TrimSuffix(filepath.ToSlash(targetPath), "/...")
	if targetPath == "" {
		targetPath = "."
	}
	target, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat analysis target: %w", err)
	}
	dir := target
	if !stat.IsDir() {
		if filepath.Ext(target) != ".go" {
			return nil, fmt.Errorf("analysis target must be a Go file or directory: %s", target)
		}
		dir = filepath.Dir(target)
	}
	mod := findGoMod(dir)
	root := dir
	if mod != "" {
		root = filepath.Dir(mod)
	}
	ws := &Workspace{RootDir: root, GoModPath: mod, Fset: token.NewFileSet(), files: make(map[*packages.Package][]*ast.File)}
	if mod == "" && !stat.IsDir() {
		return loadFile(ctx, ws, target, cfg)
	}
	if mod == "" {
		return nil, fmt.Errorf("no go.mod found for directory %s", target)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return nil, err
	}
	pattern := "./" + filepath.ToSlash(rel)
	if stat.IsDir() {
		pattern += "/..."
	}
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes | packages.NeedModule
	loaded, err := packages.Load(&packages.Config{Context: ctx, Dir: root, Fset: ws.Fset, Mode: mode, Tests: cfg.Scan.IncludeTests}, pattern)
	if err != nil {
		return nil, fmt.Errorf("load Go packages: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seen := map[*packages.Package]bool{}
	var loadErrors []string
	packages.Visit(loaded, func(pkg *packages.Package) bool {
		if seen[pkg] {
			return false
		}
		seen[pkg] = true
		ws.AllPkgs = append(ws.AllPkgs, pkg)
		for _, err := range pkg.Errors {
			loadErrors = append(loadErrors, err.Error())
		}
		return true
	}, nil)
	if len(loadErrors) > 0 {
		return nil, fmt.Errorf("load Go packages:\n%s", strings.Join(loadErrors, "\n"))
	}
	// With tests enabled, the augmented variant already contains production files.
	selected := map[string]*packages.Package{}
	for _, pkg := range loaded {
		if pkg.Name == "main" && strings.HasSuffix(pkg.PkgPath, ".test") {
			continue
		}
		files := selectFiles(ws, pkg, target, stat.IsDir(), cfg)
		if len(files) == 0 {
			continue
		}
		prev := selected[pkg.PkgPath]
		if prev == nil || (strings.Contains(pkg.ID, " [") && !strings.Contains(prev.ID, " [")) {
			selected[pkg.PkgPath] = pkg
			ws.files[pkg] = files
		}
	}
	for _, pkg := range selected {
		ws.Packages = append(ws.Packages, pkg)
	}
	sort.Slice(ws.Packages, func(i, j int) bool { return ws.Packages[i].ID < ws.Packages[j].ID })
	sort.Slice(ws.AllPkgs, func(i, j int) bool { return ws.AllPkgs[i].ID < ws.AllPkgs[j].ID })
	return ws, nil
}

func findGoMod(dir string) string {
	for {
		path := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func selectFiles(ws *Workspace, pkg *packages.Package, target string, directory bool, cfg *config.Config) []*ast.File {
	var files []*ast.File
	for _, file := range pkg.Syntax {
		name := ws.Fset.Position(file.Pos()).Filename
		if !directory && filepath.Clean(name) != target {
			continue
		}
		if directory && !within(target, name) {
			continue
		}
		if !cfg.Scan.IncludeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !cfg.Scan.IncludeGenerated && IsGeneratedFile(file) {
			continue
		}
		rel, err := filepath.Rel(ws.RootDir, name)
		if err != nil {
			continue
		}
		if excluded(filepath.ToSlash(rel), cfg) {
			continue
		}
		if cfg.Scan.MaxFileSizeBytes > 0 {
			if info, err := os.Stat(name); err != nil || info.Size() > cfg.Scan.MaxFileSizeBytes {
				continue
			}
		}
		files = append(files, file)
	}
	return files
}

func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func excluded(path string, cfg *config.Config) bool {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "vendor" && !cfg.Scan.IncludeVendor {
			return true
		}
	}
	for _, pattern := range cfg.Scan.ExcludedPaths {
		pattern = filepath.ToSlash(pattern)
		if name := strings.Trim(pattern, "/"); name == "" || (name == "vendor" && cfg.Scan.IncludeVendor) {
			continue
		}
		if matcher.New([]string{pattern}).Match(path) {
			return true
		}
	}
	return false
}

// IsGeneratedFile follows the standard Go generated-file marker convention.
func IsGeneratedFile(file *ast.File) bool {
	if file == nil {
		return false
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if comment.Pos() >= file.Package {
				continue
			}
			if strings.HasPrefix(comment.Text, "// Code generated ") && strings.HasSuffix(comment.Text, " DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}

// Files returns the files of pkg selected for analysis (target files without
// excluded or generated ones).
func (ws *Workspace) Files(pkg *packages.Package) []*ast.File {
	if files, ok := ws.files[pkg]; ok {
		return files
	}
	return pkg.Syntax
}

func NewAnalysisPass(ws *Workspace, pkg *packages.Package, reportFn func(analysis.Diagnostic)) *analysis.Pass {
	files, ok := ws.files[pkg]
	if !ok {
		files = pkg.Syntax
	}
	if reportFn == nil {
		reportFn = func(analysis.Diagnostic) {}
	}
	return &analysis.Pass{Fset: ws.Fset, Files: files, Pkg: pkg.Types, TypesInfo: pkg.TypesInfo, TypesSizes: pkg.TypesSizes, Report: reportFn, ResultOf: make(map[*analysis.Analyzer]any)}
}

func loadFile(ctx context.Context, ws *Workspace, path string, cfg *config.Config) (*Workspace, error) {
	file, err := parser.ParseFile(ws.Fset, path, nil, parser.ParseComments|parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parse Go file: %w", err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{},
		Implicits: map[ast.Node]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Scopes: map[ast.Node]*types.Scope{}, Instances: map[*ast.Ident]types.Instance{},
	}
	sizes := types.SizesFor("gc", runtime.GOARCH)
	tc := types.Config{Importer: importer.Default(), Sizes: sizes}
	tp, err := tc.Check("command-line-arguments", ws.Fset, []*ast.File{file}, info)
	if err != nil {
		return nil, fmt.Errorf("type-check Go file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkg := &packages.Package{ID: "command-line-arguments", Name: file.Name.Name, PkgPath: tp.Path(), Fset: ws.Fset, Types: tp, TypesInfo: info, TypesSizes: sizes, Syntax: []*ast.File{file}, GoFiles: []string{path}, CompiledGoFiles: []string{path}, Imports: map[string]*packages.Package{}}
	visited := map[*types.Package]*packages.Package{tp: pkg}
	var wrap func(*types.Package) *packages.Package
	wrap = func(p *types.Package) *packages.Package {
		if old := visited[p]; old != nil {
			return old
		}
		dep := &packages.Package{ID: p.Path(), Name: p.Name(), PkgPath: p.Path(), Types: p, TypesSizes: sizes, Imports: map[string]*packages.Package{}}
		visited[p] = dep
		ws.AllPkgs = append(ws.AllPkgs, dep)
		for _, imp := range p.Imports() {
			dep.Imports[imp.Path()] = wrap(imp)
		}
		return dep
	}
	for _, imp := range tp.Imports() {
		pkg.Imports[imp.Path()] = wrap(imp)
	}
	ws.AllPkgs = append(ws.AllPkgs, pkg)
	files := selectFiles(ws, pkg, path, false, cfg)
	if len(files) > 0 {
		ws.Packages = []*packages.Package{pkg}
		ws.files[pkg] = files
	}
	return ws, nil
}
