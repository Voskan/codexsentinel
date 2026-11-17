package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/cache"
	"github.com/Voskan/codexsentinel/analyzer/critsec"
	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
	"github.com/Voskan/codexsentinel/analyzer/rules/builtin"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/arch"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/deps"
	"github.com/Voskan/codexsentinel/internal/matcher"
	"github.com/Voskan/codexsentinel/metrics"
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

// Options holds per-run inputs that are not part of the configuration.
type Options struct {
	// Rules are package-level rules used for this run only, for example
	// compiled YAML rules. They are combined with the rules in the global
	// registry; a rule here replaces a registered rule with the same ID.
	// Passing rules here instead of registering them keeps repeated runs in
	// one process independent of each other.
	Rules []*rules.Rule
	// Cache, when set, stores package results instead of the directory from
	// the configuration. It is used only while scan.enable_cache is true.
	Cache *cache.Cache
	// Focus lists files, by absolute path, whose packages are analyzed
	// before the others. It is used only together with Early.
	Focus []string
	// Early, when set and at least one package contains a Focus file,
	// receives the findings of the package-level rules (built-in, YAML and
	// metrics) for those packages as soon as they are known, before the
	// remaining packages and the whole-program analyses run. The findings
	// are filtered and suppressed like the final ones and are complete for
	// files, the selected files of those packages; both use paths relative
	// to the workspace root. Findings of whole-program analyses, such as
	// taint tracking and architecture checks, are only in the final result.
	Early func(issues []result.Issue, files []string)
}

// Run loads a workspace once and analyzes its packages with bounded concurrency.
func Run(ctx context.Context, path string, cfg *config.Config) ([]result.Issue, error) {
	return RunWithOptions(ctx, path, cfg, Options{})
}

// RunWithOptions is Run with additional per-run inputs.
func RunWithOptions(ctx context.Context, path string, cfg *config.Config, opts Options) ([]result.Issue, error) {
	if cfg == nil {
		defaults := config.NewDefaultConfig()
		cfg = &defaults
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	ws, err := workspace.Load(ctx, path, cfg)
	if err != nil {
		return nil, err
	}
	ruleSet := packageRules(opts.Rules)
	pc := openPackageCache(cfg, opts, ruleSet)
	pkgs := ws.Packages
	var issues []result.Issue
	if opts.Early != nil {
		focus, rest := splitFocus(ws, opts.Focus)
		if len(focus) > 0 {
			found, err := runPackageRules(ctx, ws, cfg, ruleSet, pc, focus)
			if err != nil {
				return nil, err
			}
			files := packageFiles(ws, focus)
			opts.Early(earlyIssues(ws, cfg, found, files), files)
			issues, pkgs = found, rest
		}
	}
	found, err := runPackageRules(ctx, ws, cfg, ruleSet, pc, pkgs)
	if err != nil {
		return nil, err
	}
	issues = append(issues, found...)
	found, err = runWorkspaceAnalyses(ctx, ws, cfg)
	if err != nil {
		return nil, err
	}
	return postProcess(ws, cfg, append(issues, found...)), nil
}

// packageRules merges the registered rules with the rules of one run. The
// result is sorted by ID so that findings are produced in a stable order.
func packageRules(extra []*rules.Rule) []*rules.Rule {
	byID := map[string]*rules.Rule{}
	for _, r := range rules.All() {
		byID[r.ID] = r
	}
	for _, r := range extra {
		if r != nil && r.ID != "" {
			byID[r.ID] = r
		}
	}
	out := make([]*rules.Rule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// splitFocus separates the packages containing one of the focus files from
// the others, keeping the workspace order. Paths are compared as given and,
// when none matches, with symbolic links resolved.
func splitFocus(ws *workspace.Workspace, focus []string) (in, out []*packages.Package) {
	if len(focus) == 0 {
		return nil, ws.Packages
	}
	want := map[string]bool{}
	for _, f := range focus {
		want[filepath.Clean(f)] = true
	}
	in, out = partitionPackages(ws, func(name string) bool { return want[name] })
	if len(in) > 0 {
		return in, out
	}
	resolved := map[string]bool{}
	for _, f := range focus {
		if r, err := filepath.EvalSymlinks(f); err == nil {
			resolved[r] = true
		}
	}
	return partitionPackages(ws, func(name string) bool {
		r, err := filepath.EvalSymlinks(name)
		return err == nil && resolved[r]
	})
}

// partitionPackages separates the packages with a file for which match is
// true from the others.
func partitionPackages(ws *workspace.Workspace, match func(filename string) bool) (in, out []*packages.Package) {
	for _, pkg := range ws.Packages {
		matched := false
		for _, file := range ws.Files(pkg) {
			if match(ws.Fset.Position(file.Pos()).Filename) {
				matched = true
				break
			}
		}
		if matched {
			in = append(in, pkg)
		} else {
			out = append(out, pkg)
		}
	}
	return in, out
}

// packageFiles returns the selected files of pkgs relative to the workspace
// root, sorted and without duplicates.
func packageFiles(ws *workspace.Workspace, pkgs []*packages.Package) []string {
	seen := map[string]bool{}
	var files []string
	for _, pkg := range pkgs {
		for _, file := range ws.Files(pkg) {
			name := relativePath(ws.RootDir, ws.Fset.Position(file.Pos()).Filename)
			if !seen[name] {
				seen[name] = true
				files = append(files, name)
			}
		}
	}
	sort.Strings(files)
	return files
}

// earlyIssues post-processes the package-level findings of the focus
// packages and keeps those located in files.
func earlyIssues(ws *workspace.Workspace, cfg *config.Config, found []result.Issue, files []string) []result.Issue {
	covered := map[string]bool{}
	for _, f := range files {
		covered[f] = true
	}
	var out []result.Issue
	for _, issue := range postProcess(ws, cfg, found) {
		if covered[issue.Location.File] {
			out = append(out, issue)
		}
	}
	return out
}

// runPackageRules runs the built-in rules and ruleSet on pkgs.
func runPackageRules(ctx context.Context, ws *workspace.Workspace, cfg *config.Config, ruleSet []*rules.Rule, pc *packageCache, pkgs []*packages.Package) ([]result.Issue, error) {
	workers := cfg.Scan.Concurrency
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(workers)
	var mu sync.Mutex
	var issues []result.Issue
	for _, pkg := range pkgs {
		group.Go(func() error {
			found, err := pc.analyze(ws, pkg, func() ([]result.Issue, error) {
				return analyzePackage(groupCtx, ws, pkg, cfg, ruleSet)
			})
			if err != nil {
				return err
			}
			mu.Lock()
			issues = append(issues, found...)
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return issues, nil
}

// analyzePackage runs the enabled package-level rules on one package.
func analyzePackage(ctx context.Context, ws *workspace.Workspace, pkg *packages.Package, cfg *config.Config, ruleSet []*rules.Rule) ([]result.Issue, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ac := analyzer.NewAnalyzerContext(ws.Fset, pkg.TypesInfo, nil, "", pkg.PkgPath, nil)
	ac.Cfg, ac.RootDir = cfg, ws.RootDir
	pass := workspace.NewAnalysisPass(ws, pkg, func(d analysis.Diagnostic) {
		ac.Report(result.Issue{ID: d.Category, Description: d.Message, Severity: result.SeverityMedium, Category: "security", Location: result.NewLocationFromPos(ws.Fset.Position(d.Pos), "", pkg.PkgPath)})
	})
	ac.Files = pass.Files
	if len(pass.Files) == 0 {
		return nil, nil
	}
	ac.Filename = ws.Fset.Position(pass.Files[0].Pos()).Filename
	registerBuiltinRules(ac)
	for _, rule := range ac.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rule.Matcher != nil && ruleEnabled(rule.ID, cfg) {
			rule.Matcher(ac, pass)
		}
	}
	for _, rule := range ruleSet {
		if !rule.Enabled || rule.Engine == nil || !ruleEnabled(rule.ID, cfg) {
			continue
		}
		found, err := rule.Engine(ac)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		for _, issue := range found {
			ac.Report(issue)
		}
	}
	return append(ac.GetIssues(), metrics.RunFiles(ws.Fset, pass.Files, pkg.PkgPath, ws.RootDir, cfg.Metrics)...), nil
}

// runWorkspaceAnalyses runs the analyses that need the whole program: taint
// tracking, dependency audit, architecture, metrics and the capability lock.
// The SSA program is built once and shared between them.
func runWorkspaceAnalyses(ctx context.Context, ws *workspace.Workspace, cfg *config.Config) ([]result.Issue, error) {
	needReachability := cfg.Dependencies.Enable && cfg.Dependencies.CheckVulnerabilities && cfg.Dependencies.CheckReachability
	capsLock := capabilityLockPath(ws, cfg)
	needDeadCode := cfg.Metrics.Enable && cfg.Metrics.EnableDeadCode
	needCritsec := ruleEnabled(critsec.TxNetworkIO, cfg) || ruleEnabled(critsec.LockBlockingIO, cfg)
	var bundle *codessa.GraphBundle
	if (cfg.Taint.Enable || needReachability || needDeadCode || needCritsec || capsLock != "") && len(ws.Packages) > 0 {
		var err error
		if bundle, err = codessa.BuildFromWorkspace(ws); err != nil {
			return nil, fmt.Errorf("build SSA: %w", err)
		}
	}
	var issues []result.Issue
	add := func(found []result.Issue, err error) error {
		issues = append(issues, found...)
		return err
	}
	if cfg.Taint.Enable && bundle != nil {
		if err := add(runTaintAnalysis(ctx, ws, cfg, bundle)); err != nil {
			return nil, err
		}
	}
	if cfg.Dependencies.Enable && len(ws.GoModPaths) > 0 {
		depBundle := bundle
		if !needReachability {
			depBundle = nil
		}
		if err := add(runDependencyAnalysis(ctx, ws, cfg, depBundle)); err != nil {
			return nil, err
		}
	}
	if !cfg.Dependencies.Enable && len(ws.GoModPaths) > 0 && (cfg.Dependencies.CheckHygiene || cfg.Dependencies.CheckProvenance) {
		issues = append(issues, runModuleHygiene(ws, cfg)...)
	}
	if needCritsec && bundle != nil {
		issues = append(issues, critsec.Analyze(ws, bundle, func(id string) bool { return ruleEnabled(id, cfg) })...)
	}
	if cfg.Architecture.Enable {
		issues = append(issues, arch.RunAll(ws, bundle, cfg.Architecture)...)
	}
	if cfg.Metrics.Enable {
		issues = append(issues, runMetricsAnalysis(ws, bundle, cfg)...)
	}
	if capsLock != "" && bundle != nil {
		if err := add(runCapabilityCheck(ws, bundle, capsLock)); err != nil {
			return nil, err
		}
	}
	return issues, nil
}

// runTaintAnalysis builds SSA once for the workspace and tracks untrusted data
// from sources to sinks, following calls when interprocedural mode is enabled.
func runTaintAnalysis(ctx context.Context, ws *workspace.Workspace, cfg *config.Config, bundle *codessa.GraphBundle) ([]result.Issue, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	engine := flow.NewEngine(bundle, flow.RegistryFromConfig(cfg.Taint), flow.Options{Interprocedural: cfg.Taint.Interprocedural})
	ac := &analyzer.AnalyzerContext{Cfg: cfg, RootDir: ws.RootDir, Fset: ws.Fset}
	for _, issue := range engine.Run() {
		ac.Report(issue)
	}
	return ac.GetIssues(), ctx.Err()
}

func relativePath(root, file string) string {
	if root != "" && filepath.IsAbs(file) {
		if rel, err := filepath.Rel(root, file); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(file)
}

func ruleEnabled(id string, cfg *config.Config) bool {
	return (len(cfg.Rules.Enabled) == 0 || matcher.New(cfg.Rules.Enabled).Match(id)) && !matcher.New(cfg.Rules.Disabled).Match(id)
}

// runDependencyAnalysis audits module dependencies for known vulnerabilities
// and license policy violations. Advisory lookups that fail are reported as a
// warning so that the rest of the analysis still completes.
func runDependencyAnalysis(ctx context.Context, ws *workspace.Workspace, cfg *config.Config, bundle *codessa.GraphBundle) ([]result.Issue, error) {
	opts := deps.OptionsFromConfig(cfg.Dependencies)
	opts.Bundle = bundle
	var issues []result.Issue
	for _, goMod := range ws.GoModPaths {
		reports, err := deps.ScanDependencies(ctx, goMod, opts)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			fmt.Fprintf(os.Stderr, "Warning: dependency analysis of %s incomplete: %v\n", goMod, err)
		}
		issues = append(issues, deps.ReportIssues(reports, relativePath(ws.RootDir, goMod))...)
	}
	return issues, nil
}

// runModuleHygiene runs the offline go.mod checks when the full dependency
// audit is off. Problems reading go.mod are reported as a warning.
func runModuleHygiene(ws *workspace.Workspace, cfg *config.Config) []result.Issue {
	var issues []result.Issue
	for _, goMod := range ws.GoModPaths {
		findings, err := deps.AnalyzeGoModHygiene(goMod, deps.HygieneOptions{
			Typosquatting: cfg.Dependencies.CheckProvenance, Hygiene: cfg.Dependencies.CheckHygiene,
			AllowedPrefixes: cfg.Dependencies.AllowedPrefixes, DeniedPrefixes: cfg.Dependencies.DeniedPrefixes,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: go.mod checks of %s incomplete: %v\n", goMod, err)
		}
		issues = append(issues, deps.FindingIssues(findings, relativePath(ws.RootDir, goMod))...)
	}
	return issues
}

// capabilityLockPath returns the capability lock file to verify, or "" when
// the check is disabled or the project has no lock file.
func capabilityLockPath(ws *workspace.Workspace, cfg *config.Config) string {
	if !cfg.Dependencies.CheckCapabilities || len(ws.GoModPaths) == 0 {
		return ""
	}
	path := cfg.Dependencies.CapabilityLockfile
	if path == "" {
		path = ".codexsentinel.caps.json"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(ws.RootDir, path)
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// runCapabilityCheck reports dependencies whose reachable code gained risky
// capabilities that the lock file does not approve.
func runCapabilityCheck(ws *workspace.Workspace, bundle *codessa.GraphBundle, lockPath string) ([]result.Issue, error) {
	lock, err := deps.LoadCapabilityLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("capability lock: %w", err)
	}
	report, err := deps.AnalyzeCapabilities(ws, bundle)
	if err != nil {
		return nil, err
	}
	return deps.EscalationIssues(deps.DiffCapabilities(lock, report), relativePath(ws.RootDir, lockPath)), nil
}

// registerBuiltinRules registers all built-in security rules.
func registerBuiltinRules(ctx *analyzer.AnalyzerContext) {
	builtin.RegisterAll(ctx)
}
