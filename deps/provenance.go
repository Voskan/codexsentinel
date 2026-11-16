package deps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
)

// DefaultProxyURL is the Go module proxy used when GOPROXY is unset.
const DefaultProxyURL = "https://proxy.golang.org"

// ProxyClient reads module metadata from a Go module proxy.
type ProxyClient struct {
	BaseURL  string        // proxy root; empty disables lookups
	HTTP     *http.Client  // a 10s timeout client when nil
	CacheDir string        // directory for cached responses; empty disables caching
	CacheTTL time.Duration // lifetime of cached @latest answers (default 24h)
	// Private lists GOPRIVATE-style patterns of modules never sent to the proxy.
	Private string
}

// NewProxyClient configures a client from GOPROXY, GONOPROXY and GOPRIVATE.
// The first proxy URL in GOPROXY is used; "direct" or "off" before any URL
// disables lookups.
func NewProxyClient() *ProxyClient {
	c := &ProxyClient{BaseURL: proxyFromEnv(os.Getenv("GOPROXY")), HTTP: &http.Client{Timeout: 10 * time.Second}, CacheTTL: 24 * time.Hour}
	c.Private = os.Getenv("GONOPROXY")
	if c.Private == "" {
		c.Private = os.Getenv("GOPRIVATE")
	}
	if dir, err := os.UserCacheDir(); err == nil {
		c.CacheDir = filepath.Join(dir, "codexsentinel", "modproxy")
	}
	return c
}

func proxyFromEnv(value string) string {
	if strings.TrimSpace(value) == "" {
		return DefaultProxyURL
	}
	for _, entry := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '|' }) {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "direct" || entry == "off":
			return ""
		case strings.HasPrefix(entry, "https://") || strings.HasPrefix(entry, "http://"):
			return strings.TrimRight(entry, "/")
		}
	}
	return ""
}

var errNotFound = errors.New("not found on the module proxy")

// get fetches a proxy path. Responses for a specific version never change and
// are cached without expiry; others expire after CacheTTL.
func (c *ProxyClient) get(ctx context.Context, path string, immutable bool) ([]byte, error) {
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/" + path
	cachePath := ""
	if c.CacheDir != "" {
		sum := sha256.Sum256([]byte(endpoint))
		cachePath = filepath.Join(c.CacheDir, hex.EncodeToString(sum[:]))
		ttl := c.CacheTTL
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		if info, err := os.Stat(cachePath); err == nil && (immutable || time.Since(info.ModTime()) < ttl) {
			if data, err := os.ReadFile(cachePath); err == nil {
				return data, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //codex:ignore ssrf -- endpoint is built from the configured module proxy URL
	if err != nil {
		return nil, err
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("module proxy: %s: %s", path, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
			_ = os.WriteFile(cachePath, data, 0o600)
		}
	}
	return data, nil
}

func escapedVersionPath(mod, version, suffix string) (string, error) {
	m, err := module.EscapePath(mod)
	if err != nil {
		return "", err
	}
	v, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	return m + "/@v/" + v + suffix, nil
}

// PublishTime returns when version of mod was published.
func (c *ProxyClient) PublishTime(ctx context.Context, mod, version string) (time.Time, error) {
	path, err := escapedVersionPath(mod, version, ".info")
	if err != nil {
		return time.Time{}, err
	}
	data, err := c.get(ctx, path, true)
	if err != nil {
		return time.Time{}, err
	}
	var info struct {
		Version string
		Time    time.Time
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return time.Time{}, fmt.Errorf("module proxy: %s: %w", path, err)
	}
	return info.Time, nil
}

// LatestGoMod returns the go.mod file of the latest version of mod, which
// carries the module's deprecation notice and retractions.
func (c *ProxyClient) LatestGoMod(ctx context.Context, mod string) (*modfile.File, error) {
	escaped, err := module.EscapePath(mod)
	if err != nil {
		return nil, err
	}
	data, err := c.get(ctx, escaped+"/@latest", false)
	if err != nil {
		return nil, err
	}
	var latest struct{ Version string }
	if err := json.Unmarshal(data, &latest); err != nil || latest.Version == "" {
		return nil, fmt.Errorf("module proxy: %s/@latest: invalid response", mod)
	}
	path, err := escapedVersionPath(mod, latest.Version, ".mod")
	if err != nil {
		return nil, err
	}
	if data, err = c.get(ctx, path, true); err != nil {
		return nil, err
	}
	return modfile.ParseLax(path, data, nil)
}

// ProvenanceOptions configures CheckProvenance.
type ProvenanceOptions struct {
	// MinModuleAgeDays reports versions published fewer days ago; 0 disables.
	MinModuleAgeDays int
	AllowedPrefixes  []string
	Proxy            *ProxyClient // defaults to NewProxyClient()
	Now              func() time.Time
}

// CheckProvenance asks the module proxy when each required version was
// published, whether the module is deprecated and whether the version was
// retracted. Modules replaced by local directories and private modules are
// skipped. Findings gathered before a lookup failed are returned with the
// error.
func CheckProvenance(ctx context.Context, goModPath string, opts ProvenanceOptions) ([]ModuleFinding, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}
	proxy := opts.Proxy
	if proxy == nil {
		proxy = NewProxyClient()
	}
	if proxy.BaseURL == "" {
		return nil, nil
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	project := ""
	if f.Module != nil {
		project = f.Module.Mod.Path
	}
	eff := effectiveVersions(f)
	var (
		mu       sync.Mutex
		findings []ModuleFinding
		errs     []error
	)
	add := func(found []ModuleFinding, err error) {
		mu.Lock()
		defer mu.Unlock()
		findings = append(findings, found...)
		if err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, err)
		}
	}
	group, gctx := errgroup.WithContext(ctx)
	group.SetLimit(8)
	for _, req := range f.Require {
		mod, version := eff[req.Mod.Path][0], eff[req.Mod.Path][1]
		if version == "" || module.MatchPrefixPatterns(proxy.Private, mod) {
			continue
		}
		line := lineOf(req.Syntax)
		checkAge := opts.MinModuleAgeDays > 0 && !matchesPrefix(mod, opts.AllowedPrefixes) && !sameOwner(mod, project)
		group.Go(func() error {
			if checkAge {
				add(youngModule(gctx, proxy, mod, version, line, opts.MinModuleAgeDays, now()))
			}
			add(upstreamStatus(gctx, proxy, mod, version, line))
			return nil
		})
	}
	_ = group.Wait()
	sortFindings(findings)
	return findings, errors.Join(errs...)
}

func youngModule(ctx context.Context, proxy *ProxyClient, mod, version string, line, minDays int, now time.Time) ([]ModuleFinding, error) {
	published, err := proxy.PublishTime(ctx, mod, version)
	if err != nil || published.IsZero() {
		return nil, err
	}
	age := now.Sub(published)
	if age >= time.Duration(minDays)*24*time.Hour {
		return nil, nil
	}
	return []ModuleFinding{{
		RuleID: RuleYoungModule, Module: mod, Version: version, Line: line, Severity: result.SeverityMedium,
		Message: fmt.Sprintf("Module %s@%s was published %s ago (%s), less than the %d days required by dependencies.min_module_age_days; review new releases before adopting them.",
			mod, version, humanAge(age), published.UTC().Format(time.RFC3339), minDays),
	}}, nil
}

func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func upstreamStatus(ctx context.Context, proxy *ProxyClient, mod, version string, line int) ([]ModuleFinding, error) {
	f, err := proxy.LatestGoMod(ctx, mod)
	if err != nil {
		return nil, err
	}
	var out []ModuleFinding
	if f.Module != nil && f.Module.Deprecated != "" {
		out = append(out, ModuleFinding{
			RuleID: RuleDeprecated, Module: mod, Version: version, Line: line, Severity: result.SeverityMedium,
			Message: fmt.Sprintf("Module %s is deprecated by its authors: %s", mod, strings.TrimSpace(f.Module.Deprecated)),
		})
	}
	for _, r := range f.Retract {
		if semver.Compare(version, r.Low) < 0 || semver.Compare(version, r.High) > 0 {
			continue
		}
		why := strings.TrimSpace(r.Rationale)
		if why == "" {
			why = "no reason given"
		}
		out = append(out, ModuleFinding{
			RuleID: RuleRetracted, Module: mod, Version: version, Line: line, Severity: result.SeverityHigh,
			Message: fmt.Sprintf("Version %s of %s is retracted by its authors (%s).", version, mod, why),
		})
		break
	}
	return out, nil
}
