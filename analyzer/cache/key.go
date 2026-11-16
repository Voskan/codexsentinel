package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/types"
	"hash"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/Voskan/codexsentinel/internal/version"
	"golang.org/x/tools/go/packages"
)

// formatVersion changes whenever the layout of keys or entries changes.
const formatVersion = "codexsentinel-cache-1"

var (
	toolOnce sync.Once
	toolID   string
)

// ToolID identifies the running analyzer: its release version and commit, or,
// for development builds, a hash of the executable, so that rebuilding the
// binary invalidates every entry.
func ToolID() string {
	toolOnce.Do(func() {
		toolID = version.Version + "+" + version.Commit
		if version.Version != "dev" {
			return
		}
		exe, err := os.Executable()
		if err == nil {
			if sum, err := fileHash(exe); err == nil {
				toolID = "dev+" + sum
				return
			}
		}
		toolID = "dev+unknown"
	})
	return toolID
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Keyer computes package keys for one analysis run. The digests of imported
// packages are computed once and shared between the packages of the run.
type Keyer struct {
	base string
	mu   sync.Mutex
	deps map[*packages.Package]string
}

// NewKeyer returns a keyer whose keys depend on the analyzer, the format
// version and parts, such as the configuration and the rule set.
func NewKeyer(parts ...string) *Keyer {
	h := sha256.New()
	writeField(h, formatVersion)
	writeField(h, ToolID())
	for _, p := range parts {
		writeField(h, p)
	}
	return &Keyer{base: hex.EncodeToString(h.Sum(nil)), deps: map[*packages.Package]string{}}
}

// writeField writes s with a length prefix so that field boundaries cannot be
// confused.
func writeField(h hash.Hash, s string) {
	fmt.Fprintf(h, "%d:%s;", len(s), s)
}

// PackageKey returns the key of the results of analyzing the selected files of
// pkg. It covers the package identity, the name and content of every compiled
// file, which files are selected, and the digest of every imported package.
func (k *Keyer) PackageKey(pkg *packages.Package, selected []string) (string, error) {
	h := sha256.New()
	writeField(h, k.base)
	writeField(h, pkg.ID)
	writeField(h, pkg.PkgPath)
	for _, file := range pkg.CompiledGoFiles {
		sum, err := fileHash(file)
		if err != nil {
			return "", err
		}
		writeField(h, file)
		writeField(h, sum)
	}
	sorted := append([]string(nil), selected...)
	sort.Strings(sorted)
	for _, file := range sorted {
		writeField(h, "selected:"+file)
	}
	for _, path := range importPaths(pkg) {
		writeField(h, path)
		writeField(h, k.depDigest(pkg.Imports[path]))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func importPaths(pkg *packages.Package) []string {
	paths := make([]string, 0, len(pkg.Imports))
	for path := range pkg.Imports {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// depDigest summarizes what the analysis of an importing package can observe
// of dep, including its own imports.
//
//   - A module from the module cache is identified by its path and version;
//     the module cache is immutable.
//   - A package outside any module, such as the standard library, is
//     identified by the names, sizes and modification times of its files.
//   - Any other package (the main module, a replaced module) is identified by
//     its type-checked API: every package-level declaration with its type,
//     constant values, struct fields and methods. Changes that only touch
//     function bodies keep the digest, and so the keys of its importers.
func (k *Keyer) depDigest(dep *packages.Package) string {
	if dep == nil {
		return ""
	}
	k.mu.Lock()
	sum, ok := k.deps[dep]
	k.mu.Unlock()
	if ok {
		return sum
	}
	h := sha256.New()
	writeField(h, dep.ID)
	switch mod := dep.Module; {
	case mod != nil && mod.Version != "" && mod.Replace == nil:
		writeField(h, "module:"+mod.Path+"@"+mod.Version)
	case mod == nil:
		for _, file := range dep.CompiledGoFiles {
			writeField(h, file)
			if info, err := os.Stat(file); err == nil {
				writeField(h, fmt.Sprintf("%d/%d", info.Size(), info.ModTime().UnixNano()))
			}
		}
	default:
		writeAPI(h, dep.Types)
	}
	for _, path := range importPaths(dep) {
		writeField(h, path)
		writeField(h, k.depDigest(dep.Imports[path]))
	}
	sum = hex.EncodeToString(h.Sum(nil))
	k.mu.Lock()
	k.deps[dep] = sum
	k.mu.Unlock()
	return sum
}

func writeAPI(h hash.Hash, pkg *types.Package) {
	if pkg == nil {
		writeField(h, "no-types")
		return
	}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		writeField(h, types.ObjectString(obj, nil))
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		if named, ok := tn.Type().(*types.Named); ok {
			for i := 0; i < named.NumMethods(); i++ {
				writeField(h, types.ObjectString(named.Method(i), nil))
			}
		}
	}
}
