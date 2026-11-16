// Package deps audits module dependencies: known vulnerabilities from OSV and
// the GitHub Advisory Database, call-graph reachability and licenses.
package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

// Vulnerability is a known vulnerability affecting a module version.
type Vulnerability struct {
	Module       string            `json:"module"`    // Module path, or "stdlib"
	Version      string            `json:"version"`   // Version in use
	ID           string            `json:"id"`        // OSV, GO, GHSA or CVE identifier
	Summary      string            `json:"summary"`   // One-line summary
	Details      string            `json:"details"`   // Description
	Severity     string            `json:"severity"`  // LOW, MEDIUM, HIGH or CRITICAL
	FixedVersion string            `json:"fixed"`     // First fixed version, if known
	Aliases      []string          `json:"aliases"`   // Alternative IDs
	Reference    string            `json:"reference"` // Advisory URL
	Packages     []AffectedPackage `json:"packages,omitempty"`
	// Reachable is set when a call graph was available: true if a vulnerable
	// symbol is reachable from the program's entry points, false if not.
	Reachable *bool  `json:"reachable,omitempty"`
	CalledBy  string `json:"called_by,omitempty"`
	Symbol    string `json:"symbol,omitempty"`
}

// AffectedPackage lists the vulnerable symbols of one package.
type AffectedPackage struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

// ModuleVersion is a dependency as resolved by go.mod, after replace directives.
type ModuleVersion struct {
	Path     string // Module path that provides the code
	Version  string // Version that provides the code
	Required string // Path written in the require directive
	Indirect bool
}

// StdlibModule is the OSV package name of the Go standard library.
const StdlibModule = "stdlib"

// ReadGoMod returns the required modules of a go.mod file with replace
// directives applied, followed by the standard library at the version named
// by the toolchain or go directive. Modules replaced by local directories are
// omitted because they are part of the project itself.
func ReadGoMod(goModPath string) ([]ModuleVersion, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}
	replaced := map[string]modfile.Replace{}
	for _, r := range f.Replace {
		key := r.Old.Path
		if r.Old.Version != "" {
			key += "@" + r.Old.Version
		}
		replaced[key] = *r
	}
	var mods []ModuleVersion
	for _, req := range f.Require {
		mv := ModuleVersion{Path: req.Mod.Path, Version: req.Mod.Version, Required: req.Mod.Path, Indirect: req.Indirect}
		r, ok := replaced[req.Mod.Path+"@"+req.Mod.Version]
		if !ok {
			r, ok = replaced[req.Mod.Path]
		}
		if ok {
			if r.New.Version == "" {
				continue
			}
			mv.Path, mv.Version = r.New.Path, r.New.Version
		}
		mods = append(mods, mv)
	}
	goVersion := ""
	if f.Go != nil {
		goVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		goVersion = strings.TrimPrefix(f.Toolchain.Name, "go")
	}
	if goVersion != "" {
		if strings.Count(goVersion, ".") == 1 {
			goVersion += ".0"
		}
		mods = append(mods, ModuleVersion{Path: StdlibModule, Version: goVersion, Required: StdlibModule})
	}
	return mods, nil
}

// OSVClient queries the OSV API and the Go vulnerability database.
type OSVClient struct {
	BaseURL   string        // OSV API root, e.g. https://api.osv.dev
	GoVulnURL string        // Go vulnerability database root, e.g. https://vuln.go.dev
	HTTP      *http.Client  // HTTP client; a 15s timeout client when nil
	CacheDir  string        // Directory for cached records; empty disables caching
	CacheTTL  time.Duration // Lifetime of cached records (default 24h)
}

// NewOSVClient returns a client for the public OSV services, caching records
// under the user cache directory.
func NewOSVClient() *OSVClient {
	c := &OSVClient{BaseURL: "https://api.osv.dev", GoVulnURL: "https://vuln.go.dev", HTTP: &http.Client{Timeout: 15 * time.Second}, CacheTTL: 24 * time.Hour}
	if dir, err := os.UserCacheDir(); err == nil {
		c.CacheDir = filepath.Join(dir, "codexsentinel", "vulns")
	}
	return c
}

func (c *OSVClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

const osvBatchSize = 500

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// osvEntry is the subset of the OSV schema used here.
type osvEntry struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []AffectedPackage `json:"imports"`
		} `json:"ecosystem_specific"`
		DatabaseSpecific struct {
			URL string `json:"url"`
		} `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
		URL      string `json:"url"`
	} `json:"database_specific"`
}

// Audit returns the vulnerabilities affecting mods.
func (c *OSVClient) Audit(ctx context.Context, mods []ModuleVersion) ([]Vulnerability, error) {
	var vulns []Vulnerability
	for start := 0; start < len(mods); start += osvBatchSize {
		chunk := mods[start:min(start+osvBatchSize, len(mods))]
		ids, err := c.queryBatch(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for i, mod := range chunk {
			for _, id := range ids[i] {
				entry, err := c.fetch(ctx, id)
				if err != nil {
					return nil, err
				}
				if v, ok := entry.vulnerability(mod); ok {
					vulns = append(vulns, v)
				}
			}
		}
	}
	return vulns, nil
}

func (c *OSVClient) queryBatch(ctx context.Context, mods []ModuleVersion) ([][]string, error) {
	req := struct {
		Queries []osvQuery `json:"queries"`
	}{}
	for _, m := range mods {
		var q osvQuery
		q.Package.Name, q.Package.Ecosystem, q.Version = m.Path, "Go", strings.TrimPrefix(m.Version, "v")
		req.Queries = append(req.Queries, q)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data, err := c.do(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/v1/querybatch", body)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}
	var resp osvBatchResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}
	out := make([][]string, len(mods))
	for i := range out {
		if i < len(resp.Results) {
			for _, v := range resp.Results[i].Vulns {
				out[i] = append(out[i], v.ID)
			}
		}
	}
	return out, nil
}

func (c *OSVClient) fetch(ctx context.Context, id string) (*osvEntry, error) {
	if strings.ContainsAny(id, "/\\") || id == "" || strings.Contains(id, "..") {
		return nil, fmt.Errorf("invalid vulnerability id %q", id)
	}
	cachePath := ""
	if c.CacheDir != "" {
		cachePath = filepath.Join(c.CacheDir, id+".json")
		ttl := c.CacheTTL
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < ttl {
			if data, err := os.ReadFile(cachePath); err == nil {
				var e osvEntry
				if json.Unmarshal(data, &e) == nil && e.ID != "" {
					return &e, nil
				}
			}
		}
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/v1/vulns/" + url.PathEscape(id)
	if strings.HasPrefix(id, "GO-") && c.GoVulnURL != "" {
		endpoint = strings.TrimRight(c.GoVulnURL, "/") + "/ID/" + url.PathEscape(id) + ".json"
	}
	data, err := c.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", id, err)
	}
	var e osvEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", id, err)
	}
	if cachePath != "" {
		if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
			_ = os.WriteFile(cachePath, data, 0o600)
		}
	}
	return &e, nil
}

func (c *OSVClient) do(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return data, nil
}

// vulnerability converts the entry for mod, verifying that mod's version is
// inside an affected range.
func (e *osvEntry) vulnerability(mod ModuleVersion) (Vulnerability, bool) {
	v := Vulnerability{Module: mod.Required, Version: mod.Version, ID: e.ID, Summary: e.Summary, Details: e.Details, Aliases: e.Aliases,
		Severity: normalizeSeverity(e.DatabaseSpecific.Severity), Reference: e.DatabaseSpecific.URL}
	matched := false
	for _, a := range e.Affected {
		if a.Package.Name != mod.Path {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			if ok, fixed := inOSVRange(r.Events, mod.Version); ok {
				matched = true
				if fixed != "" && (v.FixedVersion == "" || compareVersions(fixed, v.FixedVersion) < 0) {
					v.FixedVersion = fixed
				}
			}
		}
		v.Packages = append(v.Packages, a.EcosystemSpecific.Imports...)
		if v.Reference == "" {
			v.Reference = a.DatabaseSpecific.URL
		}
	}
	if !matched {
		return Vulnerability{}, false
	}
	if v.Reference == "" {
		for _, r := range e.References {
			if r.Type == "ADVISORY" || v.Reference == "" {
				v.Reference = r.URL
			}
		}
	}
	if v.Reference == "" && strings.HasPrefix(e.ID, "GO-") {
		v.Reference = "https://pkg.go.dev/vuln/" + e.ID
	}
	if v.FixedVersion != "" && mod.Path != StdlibModule && !strings.HasPrefix(v.FixedVersion, "v") {
		v.FixedVersion = "v" + v.FixedVersion
	}
	return v, true
}

// normalizeSeverity maps advisory severities to LOW, MEDIUM, HIGH or CRITICAL.
// Records without a severity (such as the Go database) are treated as HIGH.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "HIGH"
	}
}

// AuditVulnerabilities queries OSV for the modules of a go.mod file.
func AuditVulnerabilities(ctx context.Context, goModPath string) ([]Vulnerability, error) {
	mods, err := ReadGoMod(goModPath)
	if err != nil {
		return nil, err
	}
	if len(mods) == 0 {
		return nil, nil
	}
	return NewOSVClient().Audit(ctx, mods)
}
