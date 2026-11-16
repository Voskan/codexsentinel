package deps

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/mod/modfile"
)

// Rule IDs of the go.mod hygiene and provenance checks.
const (
	RuleTyposquatting   = "dependency-typosquatting"
	RuleLocalReplace    = "gomod-local-replace"
	RuleMissingChecksum = "gomod-missing-checksum"
	RulePolicyDenied    = "dependency-policy-denied"
	RuleYoungModule     = "dependency-young-module"
	RuleRetracted       = "dependency-retracted"
	RuleDeprecated      = "dependency-deprecated"
)

// ModuleFinding is a problem with one module requirement, anchored at the
// line of its require or replace directive in go.mod.
type ModuleFinding struct {
	RuleID   string
	Module   string
	Version  string
	Line     int
	Severity result.Severity
	Message  string
	// Similar is the popular module a typosquat resembles.
	Similar string
}

// HygieneOptions configures AnalyzeGoModHygiene.
type HygieneOptions struct {
	// Typosquatting compares requirements with PopularGoModules.
	Typosquatting bool
	// Hygiene checks local replace directives and go.sum checksums.
	Hygiene         bool
	AllowedPrefixes []string
	DeniedPrefixes  []string
}

// AnalyzeGoModHygiene runs the offline checks on goModPath and its go.sum.
// Unlike ReadGoMod it keeps requirements replaced by local directories.
func AnalyzeGoModHygiene(goModPath string, opts HygieneOptions) ([]ModuleFinding, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}
	project := ""
	if f.Module != nil {
		project = f.Module.Mod.Path
	}
	var out []ModuleFinding
	for _, req := range f.Require {
		mod, line := req.Mod, lineOf(req.Syntax)
		if opts.Typosquatting && !matchesPrefix(mod.Path, opts.AllowedPrefixes) && !sameOwner(mod.Path, project) {
			if similar := typosquatOf(mod.Path); similar != "" {
				out = append(out, ModuleFinding{
					RuleID: RuleTyposquatting, Module: mod.Path, Version: mod.Version, Line: line, Severity: result.SeverityHigh, Similar: similar,
					Message: fmt.Sprintf("Module %s is not a known module but differs from the popular module %s by one or two characters; it may be a typosquatted or non-existent package name.", mod.Path, similar),
				})
			}
		}
		if denied, why := policyViolation(mod.Path, opts); denied {
			out = append(out, ModuleFinding{
				RuleID: RulePolicyDenied, Module: mod.Path, Version: mod.Version, Line: line, Severity: result.SeverityHigh,
				Message: fmt.Sprintf("Module %s %s.", mod.Path, why),
			})
		}
	}
	if opts.Hygiene {
		out = append(out, localReplaces(f)...)
		sums, err := checksumFindings(f, filepath.Join(filepath.Dir(goModPath), "go.sum"))
		if err != nil {
			return out, err
		}
		out = append(out, sums...)
	}
	sortFindings(out)
	return out, nil
}

type findingMeta struct {
	title, cwe, suggestion string
	confidence             float64
}

var findingMetas = map[string]findingMeta{
	RuleTyposquatting:   {"Possible Typosquatted Dependency", "CWE-1357", "Check that the module path is the one you meant; correct it to the well-known module or add the vetted path to dependencies.allowed_prefixes.", 0.7},
	RuleLocalReplace:    {"Local Replace Directive in go.mod", "CWE-1357", "Remove the replace directive before release, or replace with a published module version.", 1},
	RuleMissingChecksum: {"Dependency Without go.sum Checksum", "CWE-353", "Run 'go mod tidy' and commit go.sum.", 1},
	RulePolicyDenied:    {"Dependency Violates Module Policy", "CWE-1357", "Remove the dependency or have it approved and update dependencies.allowed_prefixes or denied_prefixes.", 1},
	RuleYoungModule:     {"Recently Published Dependency Version", "CWE-1357", "Review the release and its diff, or pin a version older than the configured minimum age.", 0.9},
	RuleRetracted:       {"Retracted Dependency Version", "CWE-1395", "Upgrade to a version that is not retracted (go get <module>@latest).", 1},
	RuleDeprecated:      {"Deprecated Dependency", "CWE-1104", "Migrate to the replacement named in the deprecation notice.", 1},
}

// FindingIssues converts module findings into supply-chain issues at their
// go.mod lines.
func FindingIssues(findings []ModuleFinding, goModPath string) []result.Issue {
	out := make([]result.Issue, 0, len(findings))
	for _, f := range findings {
		meta := findingMetas[f.RuleID]
		out = append(out, result.Issue{
			ID: f.RuleID, Title: meta.title, Severity: f.Severity, Category: "supply-chain", CWE: meta.cwe, OWASP: "A03:2025",
			Confidence: meta.confidence, Description: f.Message, Suggestion: meta.suggestion,
			Location: result.NewLocationFromPos(token.Position{Filename: goModPath, Line: f.Line}, "", ""),
		})
	}
	return out
}

func sortFindings(out []ModuleFinding) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
}

func lineOf(line *modfile.Line) int {
	if line == nil || line.Start.Line == 0 {
		return 1
	}
	return line.Start.Line
}

// localReplaces reports replace directives that point at a directory, which
// only exists on the machine of whoever wrote them.
func localReplaces(f *modfile.File) []ModuleFinding {
	var out []ModuleFinding
	for _, r := range f.Replace {
		if r.New.Version != "" {
			continue
		}
		out = append(out, ModuleFinding{
			RuleID: RuleLocalReplace, Module: r.Old.Path, Version: r.Old.Version, Line: lineOf(r.Syntax), Severity: result.SeverityMedium,
			Message: fmt.Sprintf("Module %s is replaced by the local directory %s; builds on other machines use different code or fail.", r.Old.Path, r.New.Path),
		})
	}
	return out
}

// effectiveVersions maps each requirement to the module version the build
// downloads, or to "" when a local directory replaces it.
func effectiveVersions(f *modfile.File) map[string][2]string {
	replaced := map[string]*modfile.Replace{}
	for _, r := range f.Replace {
		key := r.Old.Path
		if r.Old.Version != "" {
			key += "@" + r.Old.Version
		}
		replaced[key] = r
	}
	out := map[string][2]string{}
	for _, req := range f.Require {
		eff := [2]string{req.Mod.Path, req.Mod.Version}
		r := replaced[req.Mod.Path+"@"+req.Mod.Version]
		if r == nil {
			r = replaced[req.Mod.Path]
		}
		if r != nil {
			eff = [2]string{r.New.Path, r.New.Version}
		}
		out[req.Mod.Path] = eff
	}
	return out
}

// checksumFindings reports direct requirements without an h1: hash of their
// module content in go.sum.
func checksumFindings(f *modfile.File, sumPath string) ([]ModuleFinding, error) {
	eff := effectiveVersions(f)
	var direct []*modfile.Require
	for _, req := range f.Require {
		if !req.Indirect && eff[req.Mod.Path][1] != "" {
			direct = append(direct, req)
		}
	}
	if len(direct) == 0 {
		return nil, nil
	}
	sums, err := readSums(sumPath)
	if err != nil {
		return nil, err
	}
	var out []ModuleFinding
	for _, req := range direct {
		e := eff[req.Mod.Path]
		if sums[e[0]+" "+e[1]] {
			continue
		}
		why := "go.sum has no checksum for it"
		if sums == nil {
			why = "the module has no go.sum file"
		}
		out = append(out, ModuleFinding{
			RuleID: RuleMissingChecksum, Module: req.Mod.Path, Version: req.Mod.Version, Line: lineOf(req.Syntax), Severity: result.SeverityHigh,
			Message: fmt.Sprintf("Module %s@%s is required but %s, so its content is not pinned. Run 'go mod tidy' and commit go.sum.", e[0], e[1], why),
		})
	}
	return out, nil
}

// readSums returns the "path version" pairs with a module content hash, or
// nil when the file does not exist.
func readSums(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 3 && strings.HasPrefix(fields[2], "h1:") && !strings.HasSuffix(fields[1], "/go.mod") {
			out[fields[0]+" "+fields[1]] = true
		}
	}
	return out, sc.Err()
}

// matchesPrefix reports whether path equals a prefix or lies below it. A
// prefix ending in "/" or "." matches any path starting with it.
func matchesPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") ||
			((strings.HasSuffix(p, "/") || strings.HasSuffix(p, ".")) && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

func policyViolation(path string, opts HygieneOptions) (bool, string) {
	if matchesPrefix(path, opts.DeniedPrefixes) {
		return true, "matches a denied prefix in dependencies.denied_prefixes"
	}
	if len(opts.AllowedPrefixes) > 0 && !matchesPrefix(path, opts.AllowedPrefixes) {
		return true, "is not covered by dependencies.allowed_prefixes"
	}
	return false, ""
}

// ownerHosts are code hosts where the second path element names an account
// that anyone can register.
var ownerHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true, "codeberg.org": true, "gitee.com": true}

// controlledDomains publish modules only from one organization, so a module
// path under them cannot be registered by a third party.
var controlledDomains = map[string]bool{
	"golang.org": true, "google.golang.org": true, "cloud.google.com": true, "go.uber.org": true, "gopkg.in": true,
	"go.opentelemetry.io": true, "k8s.io": true, "sigs.k8s.io": true, "go.etcd.io": true, "go.mongodb.org": true,
	"gorm.io": true, "go.temporal.io": true, "connectrpc.com": true,
}

// owner returns host/account for code hosts and the host otherwise.
func owner(path string) string {
	parts := strings.Split(path, "/")
	if ownerHosts[parts[0]] && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func sameOwner(path, project string) bool {
	return project != "" && owner(path) == owner(project)
}

var majorSuffix = regexp.MustCompile(`/v[0-9]+$`)

// moduleRoot strips a major version suffix and, on code hosts, keeps only
// host/account/repository so that nested modules compare by repository.
func moduleRoot(path string) string {
	path = majorSuffix.ReplaceAllString(path, "")
	parts := strings.Split(path, "/")
	if ownerHosts[parts[0]] && len(parts) > 3 {
		path = strings.Join(parts[:3], "/")
	}
	return path
}

var popularRoots = func() map[string]string {
	out := map[string]string{}
	for _, m := range PopularGoModules {
		out[moduleRoot(m)] = m
	}
	return out
}()

// typosquatOf returns the popular module that path imitates, or "".
func typosquatOf(path string) string {
	root := moduleRoot(path)
	if _, known := popularRoots[root]; known {
		return ""
	}
	host := strings.SplitN(root, "/", 2)[0]
	if controlledDomains[host] {
		return ""
	}
	best, bestDist := "", 3
	for _, mod := range PopularGoModules {
		pr := moduleRoot(mod)
		limit := 1
		if len(pr) >= 20 {
			limit = 2
		}
		if d := typoDistance(root, pr); d <= limit && d < bestDist && plausibleSquat(root, pr) {
			best, bestDist = mod, d
		}
	}
	return best
}

// plausibleSquat requires both paths to have the same shape: the same number
// of elements, and on code hosts an account and repository that each differ
// only slightly, so that unrelated short names do not match.
func plausibleSquat(a, b string) bool {
	pa, pb := strings.Split(a, "/"), strings.Split(b, "/")
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if len(pb[i]) <= 3 && pa[i] != pb[i] {
			return false
		}
	}
	return true
}

var visualFold = strings.NewReplacer("rn", "m", "vv", "w", "1", "l", "0", "o", "-", "", "_", "", ".", "")

// typoDistance is the optimal string alignment distance between a and b,
// where paths that only differ by look-alike characters or separators count
// as one edit apart.
func typoDistance(a, b string) int {
	if a == b {
		return 0
	}
	if visualFold.Replace(a) == visualFold.Replace(b) {
		return 1
	}
	return osaDistance(a, b)
}

func osaDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
