package engine

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Voskan/codexsentinel/analyzer/cache"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/packages"
)

// packageCache reuses the package-level results of earlier runs.
type packageCache struct {
	store *cache.Cache
	keyer *cache.Keyer
}

// packageEntry is the cached result of analyzing one package.
type packageEntry struct {
	Issues []result.Issue `json:"issues"`
}

// openPackageCache returns the cache for this run, or nil when caching is
// disabled, the cache directory is unusable, or a rule cannot be identified.
func openPackageCache(cfg *config.Config, opts Options, ruleSet []*rules.Rule) *packageCache {
	if !cfg.Scan.EnableCache {
		return nil
	}
	parts := []string{configDigest(cfg)}
	for _, r := range ruleSet {
		if r.Engine == nil {
			continue
		}
		if r.Fingerprint == "" {
			return nil // results of an unidentified rule cannot be reused safely
		}
		parts = append(parts, fmt.Sprintf("%s=%s/%t", r.ID, r.Fingerprint, r.Enabled))
	}
	store := opts.Cache
	if store == nil {
		dir, err := cache.ResolveDir(cfg.Scan.CacheDir)
		if err == nil {
			store, err = cache.Open(dir)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: analysis cache disabled: %v\n", err)
			return nil
		}
	}
	return &packageCache{store: store, keyer: cache.NewKeyer(parts...)}
}

// configDigest serializes the configuration that affects package results.
// Cache placement, concurrency and report settings do not.
func configDigest(cfg *config.Config) string {
	c := *cfg
	c.Scan.EnableCache, c.Scan.CacheDir, c.Scan.Concurrency = false, "", 0
	c.Report = config.ReportConfig{}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("unencodable:%p", cfg)
	}
	return string(data)
}

// analyze returns the cached results for pkg, or runs analyze and stores its
// results. A package whose files cannot be read is analyzed without the cache.
func (pc *packageCache) analyze(ws *workspace.Workspace, pkg *packages.Package, analyze func() ([]result.Issue, error)) ([]result.Issue, error) {
	if pc == nil {
		return analyze()
	}
	var selected []string
	for _, file := range ws.Files(pkg) {
		selected = append(selected, ws.Fset.Position(file.Pos()).Filename)
	}
	key, keyErr := pc.keyer.PackageKey(pkg, selected)
	if keyErr == nil {
		var entry packageEntry
		if pc.store.Get(key, &entry) {
			return entry.Issues, nil
		}
	}
	issues, err := analyze()
	if err != nil || keyErr != nil {
		return issues, err
	}
	if err := pc.store.Put(key, packageEntry{Issues: issues}); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: write analysis cache: %v\n", err)
	}
	return issues, nil
}
