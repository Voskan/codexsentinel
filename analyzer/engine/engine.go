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
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/analysis"
)

// Run loads a workspace once and analyzes its packages with bounded concurrency.
func Run(ctx context.Context, path string, cfg *config.Config) ([]result.Issue, error) {
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
	workers := cfg.Scan.Concurrency
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(workers)
	var mu sync.Mutex
	var issues []result.Issue
	for _, pkg := range ws.Packages {
		group.Go(func() error {
			if err := groupCtx.Err(); err != nil {
				return err
			}
			ac := analyzer.NewAnalyzerContext(ws.Fset, pkg.TypesInfo, nil, "", pkg.PkgPath, nil)
			ac.Cfg, ac.RootDir = cfg, ws.RootDir
			pass := workspace.NewAnalysisPass(ws, pkg, func(d analysis.Diagnostic) {
				ac.Report(result.Issue{ID: d.Category, Description: d.Message, Severity: result.SeverityMedium, Category: "security", Location: result.NewLocationFromPos(ws.Fset.Position(d.Pos), "", pkg.PkgPath)})
			})
			ac.Files = pass.Files
			if len(pass.Files) == 0 {
				return nil
			}
			ac.Filename = ws.Fset.Position(pass.Files[0].Pos()).Filename
			registerBuiltinRules(ac)
			for _, rule := range ac.Rules {
				if err := groupCtx.Err(); err != nil {
					return err
				}
				if rule.Matcher != nil && ruleEnabled(rule.ID, cfg) {
					rule.Matcher(ac, pass)
				}
			}
			for _, rule := range rules.All() {
				if rule.Enabled && rule.Engine != nil && ruleEnabled(rule.ID, cfg) {
					found, err := rule.Engine(ac)
					if err != nil {
						return fmt.Errorf("rule %s: %w", rule.ID, err)
					}
					for _, issue := range found {
						ac.Report(issue)
					}
				}
			}
			if cfg.Metrics.Enable {
				for _, file := range pass.Files {
					found, err := analyzeSingleFileMetrics(ws.Fset.Position(file.Pos()).Filename)
					if err != nil {
						return err
					}
					for _, issue := range found {
						ac.Report(*issue)
					}
				}
			}
			mu.Lock()
			issues = append(issues, ac.GetIssues()...)
			mu.Unlock()
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	var bundle *codessa.GraphBundle
	needReachability := cfg.Dependencies.Enable && cfg.Dependencies.CheckVulnerabilities && cfg.Dependencies.CheckReachability
	capsLock := capabilityLockPath(ws, cfg)
	if (cfg.Taint.Enable || needReachability || capsLock != "") && len(ws.Packages) > 0 {
		if bundle, err = codessa.BuildFromWorkspace(ws); err != nil {
			return nil, fmt.Errorf("build SSA: %w", err)
		}
	}
	if cfg.Taint.Enable && bundle != nil {
		found, err := runTaintAnalysis(ctx, ws, cfg, bundle)
		if err != nil {
			return nil, err
		}
		issues = append(issues, found...)
	}
	if cfg.Dependencies.Enable && ws.GoModPath != "" {
		depBundle := bundle
		if !needReachability {
			depBundle = nil
		}
		found, err := runDependencyAnalysis(ctx, ws, cfg, depBundle)
		if err != nil {
			return nil, err
		}
		issues = append(issues, found...)
	}
	if cfg.Architecture.Enable {
		issues = append(issues, arch.RunAll(ws, bundle, cfg.Architecture)...)
	}
	if capsLock != "" && bundle != nil {
		found, err := runCapabilityCheck(ws, bundle, capsLock)
		if err != nil {
			return nil, err
		}
		issues = append(issues, found...)
	}
	issues = configureIssues(issues, cfg)
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		return a.ID < b.ID
	})
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
		for i := range issue.Trace {
			issue.Trace[i].Location.File = relativePath(ws.RootDir, issue.Trace[i].Location.File)
		}
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

func isDirectory(path string) bool { info, err := os.Stat(path); return err == nil && info.IsDir() }

func ruleEnabled(id string, cfg *config.Config) bool {
	return (len(cfg.Rules.Enabled) == 0 || matcher.New(cfg.Rules.Enabled).Match(id)) && !matcher.New(cfg.Rules.Disabled).Match(id)
}

func configureIssues(issues []result.Issue, cfg *config.Config) []result.Issue {
	out := make([]result.Issue, 0, len(issues))
	for _, issue := range issues {
		if !ruleEnabled(issue.ID, cfg) {
			continue
		}
		if severity, ok := cfg.Rules.SeverityOverrides[issue.ID]; ok {
			issue.Severity = result.ParseSeverity(severity)
		}
		if issue.Confidence == 0 {
			issue.Confidence = 1
		}
		if issue.Confidence < cfg.Suppression.MinConfidence {
			continue
		}
		out = append(out, issue)
	}
	return out
}

// runDependencyAnalysis audits module dependencies for known vulnerabilities
// and license policy violations. Advisory lookups that fail are reported as a
// warning so that the rest of the analysis still completes.
func runDependencyAnalysis(ctx context.Context, ws *workspace.Workspace, cfg *config.Config, bundle *codessa.GraphBundle) ([]result.Issue, error) {
	reports, err := deps.ScanDependencies(ctx, ws.GoModPath, deps.ScanOptions{
		AllowLicenses:        cfg.Dependencies.AllowLicenses,
		DenyLicenses:         cfg.Dependencies.DenyLicenses,
		CheckLicenses:        cfg.Dependencies.CheckLicenses,
		CheckVulnerabilities: cfg.Dependencies.CheckVulnerabilities,
		Bundle:               bundle,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		fmt.Fprintf(os.Stderr, "Warning: dependency analysis incomplete: %v\n", err)
	}
	return deps.ReportIssues(reports, relativePath(ws.RootDir, ws.GoModPath)), nil
}

// capabilityLockPath returns the capability lock file to verify, or "" when
// the check is disabled or the project has no lock file.
func capabilityLockPath(ws *workspace.Workspace, cfg *config.Config) string {
	if !cfg.Dependencies.CheckCapabilities || ws.GoModPath == "" {
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
	// Register command execution rule
	builtin.RegisterCommandExecRule(ctx)
	// Register SQL injection rule
	builtin.RegisterSQLInjectionRule(ctx)
	// Register XSS rule
	builtin.RegisterXSSRule(ctx)
	// Register access control rule
	builtin.RegisterAccessControlRule(ctx)
	// Register insecure design rule
	builtin.RegisterInsecureDesignRule(ctx)
	// Register data integrity rule
	builtin.RegisterDataIntegrityRule(ctx)
	// Register logging monitoring rule
	builtin.RegisterLoggingMonitoringRule(ctx)
	// Register SSRF rule
	builtin.RegisterSSRFRule(ctx)
	// Register CSRF rule
	builtin.RegisterCSRFRule(ctx)
	// Register Path Traversal rule
	builtin.RegisterPathTraversalRule(ctx)
	// Register Crypto Weak Algorithm rule
	builtin.RegisterCryptoWeakRule(ctx)
	// Register Security Misconfiguration rule
	builtin.RegisterSecurityMisconfigRule(ctx)
	// Register Authentication Bypass rule
	builtin.RegisterAuthBypassRule(ctx)
	// Register Session Management rule
	builtin.RegisterSessionManagementRule(ctx)
	// Register API Security rule
	builtin.RegisterAPISecurityRule(ctx)
	// Register GraphQL Security rule
	builtin.RegisterGraphQLSecurityRule(ctx)
	// Register JWT Security rule
	builtin.RegisterJWTSecurityRule(ctx)
	// Register WebSocket Security rule
	builtin.RegisterWebSocketSecurityRule(ctx)
	// Register hardcoded secret rule
	builtin.RegisterHardcodedSecretRule(ctx)
}
