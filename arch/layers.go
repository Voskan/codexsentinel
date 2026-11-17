// Package arch checks architectural rules: layer dependencies, import cycles,
// oversized types and infrastructure types leaking across layer boundaries.
package arch

import (
	"fmt"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// LayerViolation is a dependency from one layer to a layer it may not use.
type LayerViolation struct {
	FromLayer string
	ToLayer   string
	FromPkg   string
	ToPkg     string
	FuncName  string // calling function, empty for import violations
	TargetSym string // called symbol, or the imported package
	Pos       token.Position
}

type layerDef struct {
	name     string
	patterns []string
}

// Layering maps packages to layers and decides which dependencies are allowed.
type Layering struct {
	layers  []layerDef
	allowed map[string]map[string]bool
	// Configured reports whether the layers come from the user's configuration.
	Configured bool
}

// DefaultLayers is the Clean/Hexagonal layout used when none is configured.
var DefaultLayers = map[string][]string{
	"delivery":   {"handler", "controller", "delivery", "transport", "api"},
	"usecase":    {"usecase", "application"},
	"service":    {"service"},
	"port":       {"port"},
	"repository": {"repository", "repo", "adapter", "store", "db", "infra"},
	"domain":     {"domain", "entity", "model"},
}

// DefaultAllowedDeps lists the layers each default layer may depend on.
var DefaultAllowedDeps = map[string][]string{
	"delivery":   {"usecase", "service", "domain"},
	"usecase":    {"domain", "port"},
	"service":    {"usecase", "domain", "repository", "port"},
	"port":       {"domain"},
	"repository": {"domain", "port"},
	"domain":     {},
}

// NewLayering builds the layer model from configuration, falling back to the
// default layout when no layers are configured.
func NewLayering(cfg config.ArchConfig) *Layering {
	layers, allowed, configured := cfg.Layers, cfg.AllowedDeps, true
	if len(layers) == 0 {
		layers, allowed, configured = DefaultLayers, DefaultAllowedDeps, false
	}
	l := &Layering{allowed: map[string]map[string]bool{}, Configured: configured}
	names := make([]string, 0, len(layers))
	for name := range layers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var patterns []string
		for _, p := range layers[name] {
			if p = strings.Trim(strings.TrimSpace(p), "/"); p != "" {
				patterns = append(patterns, p)
			}
		}
		l.layers = append(l.layers, layerDef{name: name, patterns: patterns})
		l.allowed[name] = map[string]bool{}
		for _, to := range allowed[name] {
			l.allowed[name][to] = true
		}
	}
	return l
}

// LayerOf returns the layer of a package path relative to its module root, or
// "" when it belongs to no layer. Patterns are path segments ("handler" also
// matches "handlers") or globs over the relative path ("internal/api/*"). The
// deepest matching segment wins.
func (l *Layering) LayerOf(relPath string) string {
	segs := strings.Split(relPath, "/")
	best, bestIdx := "", -1
	for _, layer := range l.layers {
		for _, p := range layer.patterns {
			if strings.ContainsAny(p, "*?[") || strings.Contains(p, "/") {
				if globMatch(strings.TrimSuffix(p, "/..."), relPath) && len(segs) > bestIdx {
					best, bestIdx = layer.name, len(segs)
				}
				continue
			}
			for i, s := range segs {
				if (s == p || s == p+"s") && i > bestIdx {
					best, bestIdx = layer.name, i
				}
			}
		}
	}
	return best
}

func globMatch(pattern, rel string) bool {
	if ok, _ := path.Match(pattern, rel); ok {
		return true
	}
	return strings.HasPrefix(rel, pattern+"/") || rel == pattern
}

// Allowed reports whether layer from may depend on layer to.
func (l *Layering) Allowed(from, to string) bool {
	return from == to || from == "" || to == "" || l.allowed[from][to]
}

// moduleIndex relates package paths of the analyzed modules to their
// directories relative to the workspace root, which layer patterns match.
// A go.work workspace has several main modules, each in its own directory.
type moduleIndex struct {
	modules []mainModule // longest path first
	pkgs    map[string]*packages.Package
}

type mainModule struct {
	path string // module path
	dir  string // slash-separated directory relative to the workspace root
}

func newModuleIndex(ws *workspace.Workspace) moduleIndex {
	idx := moduleIndex{pkgs: map[string]*packages.Package{}}
	seen := map[string]bool{}
	for _, pkg := range ws.Packages {
		if m := pkg.Module; m != nil && m.Main && !seen[m.Path] {
			seen[m.Path] = true
			dir := "."
			if m.Dir != "" && ws.RootDir != "" {
				if rel, err := filepath.Rel(ws.RootDir, m.Dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					dir = filepath.ToSlash(rel)
				}
			}
			idx.modules = append(idx.modules, mainModule{path: m.Path, dir: dir})
		}
		idx.pkgs[pkg.PkgPath] = pkg
	}
	sort.Slice(idx.modules, func(i, j int) bool { return len(idx.modules[i].path) > len(idx.modules[j].path) })
	return idx
}

func (m moduleIndex) rel(pkgPath string) (string, bool) {
	if len(m.modules) == 0 {
		return pkgPath, true
	}
	for _, mod := range m.modules {
		if pkgPath == mod.path {
			return mod.dir, true
		}
		if strings.HasPrefix(pkgPath, mod.path+"/") {
			return path.Join(mod.dir, strings.TrimPrefix(pkgPath, mod.path+"/")), true
		}
	}
	return "", false
}

// layer returns the layer of a package. With the default layout, main
// packages are composition roots that wire every layer together and belong to
// none, even under a directory such as cmd/api.
func (m moduleIndex) layer(l *Layering, pkgPath string) string {
	rel, ok := m.rel(pkgPath)
	if !ok {
		return ""
	}
	if pkg := m.pkgs[pkgPath]; pkg != nil && pkg.Name == "main" && !l.Configured {
		return ""
	}
	return l.LayerOf(rel)
}

// AnalyzeLayering reports calls (when a call graph is available) and imports
// that cross from a layer into one it may not depend on. An import is only
// reported when no call between the two packages was.
func AnalyzeLayering(ws *workspace.Workspace, bundle *codessa.GraphBundle, l *Layering) []LayerViolation {
	idx := newModuleIndex(ws)
	var out []LayerViolation
	reported := map[[2]string]bool{}
	if bundle != nil {
		for _, fn := range bundle.TargetFunctions() {
			if fn.Pkg == nil {
				continue
			}
			from := fn.Pkg.Pkg.Path()
			fromLayer := idx.layer(l, from)
			if fromLayer == "" {
				continue
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					call, ok := instr.(ssa.CallInstruction)
					if !ok {
						continue
					}
					callee := call.Common().StaticCallee()
					if callee == nil || callee.Pkg == nil || isInit(callee) {
						continue
					}
					to := callee.Pkg.Pkg.Path()
					toLayer := idx.layer(l, to)
					if to == from || l.Allowed(fromLayer, toLayer) {
						continue
					}
					reported[[2]string{from, to}] = true
					out = append(out, LayerViolation{FromLayer: fromLayer, ToLayer: toLayer, FromPkg: from, ToPkg: to,
						FuncName: fn.RelString(fn.Pkg.Pkg), TargetSym: callee.String(), Pos: bundle.Fset.Position(instr.Pos())})
				}
			}
		}
	}
	for _, pkg := range ws.Packages {
		fromLayer := idx.layer(l, pkg.PkgPath)
		if fromLayer == "" {
			continue
		}
		for _, file := range ws.Files(pkg) {
			for _, spec := range file.Imports {
				to, err := strconv.Unquote(spec.Path.Value)
				if err != nil || reported[[2]string{pkg.PkgPath, to}] {
					continue
				}
				toLayer := idx.layer(l, to)
				if to == pkg.PkgPath || l.Allowed(fromLayer, toLayer) {
					continue
				}
				out = append(out, LayerViolation{FromLayer: fromLayer, ToLayer: toLayer, FromPkg: pkg.PkgPath, ToPkg: to,
					TargetSym: to, Pos: ws.Fset.Position(spec.Pos())})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Offset < out[j].Pos.Offset
	})
	return out
}

// isInit reports whether fn is a package initializer, whose calls to imported
// packages' initializers are implied by imports.
func isInit(fn *ssa.Function) bool {
	return fn.Parent() == nil && fn.Signature.Recv() == nil && (fn.Name() == "init" || strings.HasPrefix(fn.Name(), "init#"))
}

// Describe renders the violation for reports.
func (v LayerViolation) Describe() string {
	if v.FuncName != "" {
		return fmt.Sprintf("%s (layer %q) calls %s in layer %q, which it may not depend on.", v.FuncName, v.FromLayer, v.TargetSym, v.ToLayer)
	}
	return fmt.Sprintf("Package %s (layer %q) imports %s (layer %q), which it may not depend on.", v.FromPkg, v.FromLayer, v.ToPkg, v.ToLayer)
}
