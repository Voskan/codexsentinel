package deps

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/config"
	"golang.org/x/tools/go/ssa"
)

// DependencyReport aggregates security and license information per module.
type DependencyReport struct {
	Module        string // e.g. github.com/foo/bar, or "stdlib"
	Version       string // e.g. v1.2.3
	License       string // e.g. MIT
	LicenseStatus string // ALLOWED / DENIED / UNKNOWN
	LicenseFile   string // path/to/LICENSE

	Vulnerabilities []Vulnerability  // Known vulnerabilities affecting Version
	SuspiciousFiles []EntropyFinding // High-entropy values in vendored code
	Findings        []ModuleFinding  // go.mod hygiene and provenance problems
}

// ScanOptions configures ScanDependencies.
type ScanOptions struct {
	AllowLicenses        []string
	DenyLicenses         []string
	CheckLicenses        bool
	CheckVulnerabilities bool
	// Bundle, when set, is used to decide whether vulnerable symbols are
	// reachable from the program's entry points.
	Bundle *codessa.GraphBundle
	OSV    *OSVClient  // defaults to NewOSVClient()
	GHSA   *GHSAClient // defaults to NewGHSAClient()

	// CheckHygiene reports local replace directives and missing checksums.
	CheckHygiene bool
	// CheckProvenance reports typosquatted names and policy violations, and,
	// together with CheckVulnerabilities, asks the module proxy for young,
	// deprecated and retracted modules.
	CheckProvenance  bool
	MinModuleAgeDays int
	AllowedPrefixes  []string
	DeniedPrefixes   []string
	Proxy            *ProxyClient // defaults to NewProxyClient()
}

// OptionsFromConfig returns the scan options set by a dependencies section.
func OptionsFromConfig(c config.DependencyConfig) ScanOptions {
	return ScanOptions{
		AllowLicenses: c.AllowLicenses, DenyLicenses: c.DenyLicenses, CheckLicenses: c.CheckLicenses,
		CheckVulnerabilities: c.CheckVulnerabilities, CheckHygiene: c.CheckHygiene, CheckProvenance: c.CheckProvenance,
		MinModuleAgeDays: c.MinModuleAgeDays, AllowedPrefixes: c.AllowedPrefixes, DeniedPrefixes: c.DeniedPrefixes,
	}
}

// ScanDependencies audits the modules of goModPath. When an advisory source
// fails, the reports gathered so far are returned together with the error.
func ScanDependencies(ctx context.Context, goModPath string, opts ScanOptions) ([]DependencyReport, error) {
	mods, err := ReadGoMod(goModPath)
	if err != nil {
		return nil, err
	}
	var errs []error
	licenses := map[string]LicenseFinding{}
	if opts.CheckLicenses {
		found, err := AnalyzeLicenses(goModPath, opts.AllowLicenses, opts.DenyLicenses)
		if err != nil {
			errs = append(errs, fmt.Errorf("license scan: %w", err))
		}
		for _, f := range found {
			licenses[f.Module] = f
		}
	}
	byModule := map[string][]Vulnerability{}
	if opts.CheckVulnerabilities && len(mods) > 0 {
		vulns, err := collectVulnerabilities(ctx, mods, opts)
		if err != nil {
			errs = append(errs, err)
		}
		ApplyReachability(opts.Bundle, vulns)
		for _, v := range vulns {
			byModule[v.Module] = append(byModule[v.Module], v)
		}
	}
	entropy := vendorEntropy(filepath.Dir(goModPath))
	findings, err := moduleFindings(ctx, goModPath, opts)
	if err != nil {
		errs = append(errs, err)
	}

	reports := make([]DependencyReport, 0, len(mods))
	for _, m := range mods {
		r := DependencyReport{Module: m.Required, Version: m.Version, Vulnerabilities: byModule[m.Required], SuspiciousFiles: entropy[m.Required]}
		if lic, ok := licenses[m.Required]; ok {
			r.License, r.LicenseFile, r.LicenseStatus = lic.License, lic.LicenseFile, "UNKNOWN"
			if lic.Allowed {
				r.LicenseStatus = "ALLOWED"
			} else if lic.Denied {
				r.LicenseStatus = "DENIED"
			}
		}
		reports = append(reports, r)
	}
	return attachFindings(reports, findings), errors.Join(errs...)
}

// moduleFindings runs the go.mod hygiene and provenance checks enabled in opts.
func moduleFindings(ctx context.Context, goModPath string, opts ScanOptions) ([]ModuleFinding, error) {
	if !opts.CheckHygiene && !opts.CheckProvenance {
		return nil, nil
	}
	var errs []error
	found, err := AnalyzeGoModHygiene(goModPath, HygieneOptions{
		Typosquatting: opts.CheckProvenance, Hygiene: opts.CheckHygiene,
		AllowedPrefixes: opts.AllowedPrefixes, DeniedPrefixes: opts.DeniedPrefixes,
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("go.mod hygiene: %w", err))
	}
	if opts.CheckProvenance && opts.CheckVulnerabilities {
		online, err := CheckProvenance(ctx, goModPath, ProvenanceOptions{
			MinModuleAgeDays: opts.MinModuleAgeDays, AllowedPrefixes: opts.AllowedPrefixes, Proxy: opts.Proxy,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("module provenance: %w", err))
		}
		found = append(found, online...)
		sortFindings(found)
	}
	return found, errors.Join(errs...)
}

// attachFindings adds each finding to the report of its module, creating
// reports for modules that ReadGoMod leaves out, such as local replacements.
func attachFindings(reports []DependencyReport, findings []ModuleFinding) []DependencyReport {
	index := map[string]int{}
	for i, r := range reports {
		index[r.Module] = i
	}
	for _, f := range findings {
		i, ok := index[f.Module]
		if !ok {
			reports = append(reports, DependencyReport{Module: f.Module, Version: f.Version})
			i = len(reports) - 1
			index[f.Module] = i
		}
		reports[i].Findings = append(reports[i].Findings, f)
	}
	return reports
}

// FindVulnerabilities queries the advisory databases for the modules of
// goModPath and, when bundle is set, decides which vulnerabilities are
// reachable. Vulnerabilities found before a source failed are returned with
// the error.
func FindVulnerabilities(ctx context.Context, goModPath string, bundle *codessa.GraphBundle, osv *OSVClient) ([]Vulnerability, error) {
	mods, err := ReadGoMod(goModPath)
	if err != nil {
		return nil, err
	}
	vulns, err := collectVulnerabilities(ctx, mods, ScanOptions{OSV: osv})
	ApplyReachability(bundle, vulns)
	return vulns, err
}

func collectVulnerabilities(ctx context.Context, mods []ModuleVersion, opts ScanOptions) ([]Vulnerability, error) {
	osv := opts.OSV
	if osv == nil {
		osv = NewOSVClient()
	}
	vulns, err := osv.Audit(ctx, mods)
	if err != nil {
		return nil, fmt.Errorf("vulnerability scan: %w", err)
	}
	ghsa := opts.GHSA
	if ghsa == nil {
		ghsa = NewGHSAClient()
	}
	extra, err := ghsa.Audit(ctx, mods)
	seen := map[string]bool{}
	for _, v := range vulns {
		seen[v.Module+"/"+v.ID] = true
		for _, a := range v.Aliases {
			seen[v.Module+"/"+a] = true
		}
	}
	for _, v := range extra {
		if !seen[v.Module+"/"+v.ID] {
			vulns = append(vulns, v)
		}
	}
	if err != nil {
		return vulns, fmt.Errorf("github advisories: %w", err)
	}
	return vulns, nil
}

// ApplyReachability marks each vulnerability with known affected symbols as
// reachable or unreachable from the bundle's entry points. Unreachable
// vulnerabilities are downgraded to LOW severity.
func ApplyReachability(bundle *codessa.GraphBundle, vulns []Vulnerability) {
	if bundle == nil || bundle.Program == nil {
		return
	}
	reachable := bundle.ReachableFrom(programRoots(bundle))
	index := map[string]map[string]*ssa.Function{}
	for fn := range reachable {
		pkg, name := symbolOf(fn)
		if pkg == "" {
			continue
		}
		if index[pkg] == nil {
			index[pkg] = map[string]*ssa.Function{}
		}
		if _, ok := index[pkg][name]; !ok {
			index[pkg][name] = fn
		}
	}
	for i := range vulns {
		v := &vulns[i]
		if len(v.Packages) == 0 {
			continue
		}
		var hit *ssa.Function
		symbol := ""
		for _, p := range v.Packages {
			if hit != nil {
				break
			}
			if len(p.Symbols) == 0 {
				if pkg := bundle.Program.ImportedPackage(p.Path); pkg != nil {
					if init := pkg.Func("init"); init != nil && reachable[init] {
						hit, symbol = init, p.Path
					}
				}
				continue
			}
			for _, s := range p.Symbols {
				if fn, ok := index[p.Path][s]; ok {
					hit, symbol = fn, p.Path+"."+s
					break
				}
			}
		}
		yes := hit != nil
		v.Reachable = &yes
		if yes {
			v.Symbol = symbol
			v.CalledBy = callerOf(bundle, hit, reachable)
		} else {
			v.Severity = "LOW"
		}
	}
}

// programRoots returns main and init of the main packages when the module
// builds commands; for a library it returns its whole exported API.
func programRoots(bundle *codessa.GraphBundle) []*ssa.Function {
	var roots []*ssa.Function
	for _, pkg := range bundle.Packages {
		if pkg == nil || pkg.Pkg.Name() != "main" {
			continue
		}
		for _, name := range []string{"main", "init"} {
			if fn := pkg.Func(name); fn != nil {
				roots = append(roots, fn)
			}
		}
	}
	if len(roots) == 0 {
		return bundle.Entrypoints()
	}
	return roots
}

// symbolOf names fn the way vulnerability databases do: "Func" or "Type.Method".
func symbolOf(fn *ssa.Function) (pkg, name string) {
	if o := fn.Origin(); o != nil {
		fn = o
	}
	for fn.Parent() != nil {
		fn = fn.Parent()
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil {
		return "", ""
	}
	name = obj.Name()
	if recv := obj.Type().(*types.Signature).Recv(); recv != nil {
		t := recv.Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if named, ok := types.Unalias(t).(*types.Named); ok {
			name = named.Obj().Name() + "." + name
		}
	}
	return obj.Pkg().Path(), name
}

// callerOf returns a reachable function calling fn, preferring project code.
func callerOf(bundle *codessa.GraphBundle, fn *ssa.Function, reachable map[*ssa.Function]bool) string {
	node := bundle.CallGraph.Nodes[fn]
	if node == nil {
		return ""
	}
	var best *ssa.Function
	for _, e := range node.In {
		caller := e.Caller.Func
		if caller == nil || !reachable[caller] {
			continue
		}
		if bundle.IsTarget(caller) {
			return caller.String()
		}
		if best == nil {
			best = caller
		}
	}
	if best != nil {
		return best.String()
	}
	return ""
}

// ReportIssues converts dependency reports into issues anchored at goModPath.
func ReportIssues(reports []DependencyReport, goModPath string) []result.Issue {
	loc := result.NewLocationFromPos(token.Position{Filename: goModPath, Line: 1}, "", "")
	var issues []result.Issue
	for _, r := range reports {
		if r.LicenseStatus == "DENIED" {
			issues = append(issues, result.Issue{
				ID: "license-denied", Title: "Denied License Detected", Severity: result.SeverityHigh, Category: "license", Location: loc,
				Description: fmt.Sprintf("Module %s@%s uses denied license %s.", r.Module, r.Version, r.License),
				Suggestion:  "Replace the dependency or obtain approval for its license.",
			})
		}
		for _, v := range r.Vulnerabilities {
			issues = append(issues, vulnerabilityIssue(r, v, loc))
		}
		issues = append(issues, FindingIssues(r.Findings, goModPath)...)
		for _, e := range r.SuspiciousFiles {
			issues = append(issues, result.Issue{
				ID: "high-entropy-string", Title: "High Entropy String in Vendored Code", Severity: result.SeverityMedium, Category: "security",
				Location:    result.NewLocationFromPos(token.Position{Filename: e.File, Line: e.Line}, "", ""),
				Description: fmt.Sprintf("Possible secret in vendored module %s.", r.Module),
				Suggestion:  "Check whether the vendored code embeds a credential.",
			})
		}
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Description < issues[j].Description })
	return issues
}

func vulnerabilityIssue(r DependencyReport, v Vulnerability, loc result.Location) result.Issue {
	module := r.Module
	if module == StdlibModule {
		module = "Go standard library"
	}
	desc := fmt.Sprintf("%s %s is affected by %s", module, r.Version, v.ID)
	if v.Summary != "" {
		desc += ": " + v.Summary
	}
	desc += "."
	switch {
	case v.Reachable != nil && *v.Reachable && v.CalledBy != "":
		desc += fmt.Sprintf(" Vulnerable symbol %s is called from %s.", v.Symbol, v.CalledBy)
	case v.Reachable != nil && *v.Reachable:
		desc += fmt.Sprintf(" Vulnerable symbol %s is reachable.", v.Symbol)
	case v.Reachable != nil:
		desc += " (Unreachable in call graph)"
	}
	suggestion := "No fixed version is published yet; check the advisory for mitigations."
	if v.FixedVersion != "" {
		if r.Module == StdlibModule {
			suggestion = fmt.Sprintf("Upgrade the Go toolchain to %s or later.", v.FixedVersion)
		} else {
			suggestion = fmt.Sprintf("Upgrade %s to %s or later (go get %s@%s).", r.Module, v.FixedVersion, r.Module, v.FixedVersion)
		}
	}
	issue := result.Issue{
		ID: "dependency-vulnerability", Title: "Vulnerable Dependency", Severity: result.ParseSeverity(v.Severity), Category: "supply-chain", CWE: "CWE-1395", OWASP: "A03:2025",
		Location: loc, Description: desc, Suggestion: suggestion, Reachable: v.Reachable, Confidence: 1,
	}
	if v.Reference != "" {
		issue.References = []string{v.Reference}
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			issue.References = append(issue.References, "https://www.cve.org/CVERecord?id="+a)
		}
	}
	return issue
}

// vendorEntropy scans vendored sources for high-entropy strings, grouped by module.
func vendorEntropy(modDir string) map[string][]EntropyFinding {
	vendorDir := filepath.Join(modDir, "vendor")
	if stat, err := os.Stat(vendorDir); err != nil || !stat.IsDir() {
		return nil
	}
	findings, err := AnalyzeHighEntropyStrings(collectGoFiles(vendorDir), 20, 4.2)
	if err != nil {
		return nil
	}
	out := map[string][]EntropyFinding{}
	for _, f := range findings {
		if mod := extractVendorModule(f.File); mod != "" {
			out[mod] = append(out[mod], f)
		}
	}
	return out
}

// collectGoFiles recursively collects all .go files under root.
func collectGoFiles(root string) []string {
	var files []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// extractVendorModule extracts the module path from a vendored file path,
// e.g. vendor/github.com/foo/bar/file.go → github.com/foo/bar.
func extractVendorModule(path string) string {
	path = filepath.ToSlash(path)
	idx := strings.Index(path, "vendor/")
	if idx == -1 {
		return ""
	}
	parts := strings.Split(path[idx+7:], "/")
	if len(parts) >= 3 {
		return strings.Join(parts[0:3], "/")
	}
	return ""
}
