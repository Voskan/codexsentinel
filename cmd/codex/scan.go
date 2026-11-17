package codex

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/baseline"
	"github.com/Voskan/codexsentinel/analyzer/cache"
	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/fixer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
	"github.com/Voskan/codexsentinel/analyzer/rules/yaml"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/assets"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/deps"
	"github.com/Voskan/codexsentinel/internal/git"
	"github.com/Voskan/codexsentinel/internal/logx"
	"github.com/Voskan/codexsentinel/report"
	"github.com/Voskan/codexsentinel/report/formats"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewScanCmd returns the `scan` command that analyzes the target source code.
func NewScanCmd() *cobra.Command {
	var opts scanOptions

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run static analysis on the target source code",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("ignore-file") {
				opts.ignoreFile = ""
			}
			if len(args) > 0 {
				opts.path = args[0]
			}
			return runScan(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.path, "path", "p", ".", "Target directory or file to scan")
	cmd.Flags().StringVarP(&opts.format, "format", "f", "sarif", "Output report format: sarif, html, markdown, json, agent, github, gitlab")
	cmd.Flags().StringVarP(&opts.outPath, "out", "o", "", "Path to write the output report to")
	cmd.Flags().BoolVar(&opts.strict, "strict", false, "Exit with code 1 if issues are found")
	cmd.Flags().StringVar(&opts.ignoreFile, "ignore-file", ".codexsentinel.ignore", "Path to ignore file (default: suppression.ignore_file from the config, relative to the project root)")
	cmd.Flags().BoolVar(&opts.depsOnly, "deps", false, "Run dependency analysis only")
	cmd.Flags().StringVar(&opts.configFile, "config", "", "Path to a custom config file")
	cmd.Flags().StringVar(&opts.severity, "severity", "", "Filter issues by severity (low, medium, high, critical)")
	cmd.Flags().BoolVar(&opts.fix, "fix", false, "Apply suggested fixes to the source files")
	cmd.Flags().StringVar(&opts.baseline, "baseline", "", "Report only findings that are not recorded in this baseline file")
	cmd.Flags().StringVar(&opts.diffRef, "diff", "", "Report only findings on lines changed since this git reference (e.g. origin/main)")
	cmd.Flags().BoolVar(&opts.noCache, "no-cache", false, "Do not read or write the analysis cache")
	cmd.Flags().StringVar(&opts.githubSummary, "github-summary", "",
		"Append a Markdown summary to this file (default with --format github: $GITHUB_STEP_SUMMARY)")
	cmd.Flags().BoolVar(&opts.forbidSuppressions, "forbid-new-suppressions", false,
		"Fail when the changes since --diff (default HEAD) add inline ignores, ignore-file entries or weaker settings; "+
			git.AllowSuppressionsEnv+"=1 approves them")

	return cmd
}

// scanOptions holds the flags of the scan command.
type scanOptions struct {
	path       string
	format     string
	outPath    string
	strict     bool
	ignoreFile string
	depsOnly   bool
	configFile string
	severity   string
	fix        bool
	baseline   string
	diffRef    string
	noCache    bool
	// forbidSuppressions reports suppressions added since diffRef.
	forbidSuppressions bool
	// githubSummary is the file that receives a Markdown job summary.
	githubSummary string
}

// runScan handles the main scan logic
func runScan(ctx context.Context, opts scanOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	targetPath := normalizeTargetPath(opts.path)
	format, outPath, strict, severity := opts.format, opts.outPath, opts.strict, opts.severity

	// Initialize logger
	if err := logx.Init(true); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logx.Sync()

	logger := logx.L()
	logger.Infof("Starting CodexSentinel analysis on path: %s", targetPath)

	// Get Git metadata if available
	gitMetadata := getGitMetadata(logger)

	var results []result.Issue
	var err error
	cfg, err := loadConfig(opts.configFile, logger)
	if err != nil {
		return err
	}
	cfg.Scan.EnableCache = cfg.Scan.EnableCache && !opts.noCache
	if outPath == "" && format == "github" {
		outPath = "-" // workflow commands only work on stdout
	}
	if outPath == "" && cfg.Report.OutputDir != "" {
		outPath = filepath.Join(cfg.Report.OutputDir, defaultOutputPath(format))
	}

	if opts.depsOnly {
		// Run only dependency analysis
		logger.Infof("Running dependency analysis only")
		results, err = runDependencyAnalysis(ctx, targetPath, cfg, logger)
		if err != nil {
			return fmt.Errorf("dependency analysis failed: %w", err)
		}
	} else {
		// Run full analysis
		results, err = runFullAnalysis(ctx, targetPath, opts.ignoreFile, cfg, severity, logger)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
	}
	if results, err = applyBaselineAndDiff(ctx, targetPath, opts, results, logger); err != nil {
		return err
	}
	guard, err := checkNewSuppressions(ctx, targetPath, opts, cfg, logger)
	if err != nil {
		return err
	}

	logger.Infof("Analysis completed, found %d issues", len(results))

	if opts.fix {
		if err := applyFixes(targetPath, results, logger); err != nil {
			return fmt.Errorf("failed to apply fixes: %w", err)
		}
	}

	all := append(guard, results...)
	if err := publishResults(all, format, outPath, opts.githubSummary, gitMetadata, logger); err != nil {
		return err
	}

	// Exit code control: added suppressions always fail the scan.
	if count := len(guard) + failingIssues(results, strict, cfg.Report.FailOnSeverity); count > 0 {
		return &IssuesFoundError{Count: count}
	}
	return nil
}

// publishResults writes the report, prints the summary (to stderr when the
// report goes to stdout) and appends the job summary.
func publishResults(all []result.Issue, format, outPath, githubSummary string, gitMetadata *report.GitMetadata, logger *zap.SugaredLogger) error {
	if err := generateReport(all, format, outPath, gitMetadata, logger); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	summaryOutput := io.Writer(os.Stdout)
	if outPath == "-" {
		summaryOutput = os.Stderr
	}
	printSummary(summaryOutput, all)
	if err := writeGitHubSummary(githubSummary, format, all); err != nil {
		return fmt.Errorf("failed to write job summary: %w", err)
	}
	return nil
}

// writeGitHubSummary appends the Markdown job summary to the given file, or
// to $GITHUB_STEP_SUMMARY for the github format.
func writeGitHubSummary(path, format string, results []result.Issue) error {
	if path == "" && format == "github" {
		path = os.Getenv("GITHUB_STEP_SUMMARY")
	}
	if path == "" {
		return nil
	}
	return formats.AppendGitHubStepSummary(report.FromResults(results), path)
}

// checkNewSuppressions reports suppressions added since the diff reference
// (HEAD by default) when the policy is enabled by flag or configuration. The
// findings bypass inline ignores, the ignore file and the baseline, so a
// suppression cannot hide itself.
func checkNewSuppressions(ctx context.Context, targetPath string, opts scanOptions, cfg *config.Config, logger *zap.SugaredLogger) ([]result.Issue, error) {
	if !opts.forbidSuppressions && !cfg.Suppression.ForbidNewSuppressions {
		return nil, nil
	}
	if approved, _ := strconv.ParseBool(os.Getenv(git.AllowSuppressionsEnv)); approved {
		logger.Infof("New suppressions approved by %s", git.AllowSuppressionsEnv)
		return nil, nil
	}
	ref := opts.diffRef
	if ref == "" {
		ref = "HEAD"
	}
	root, err := workspace.ProjectRoot(targetPath)
	if err != nil {
		return nil, err
	}
	found, err := git.ScanAddedSuppressions(ctx, root, ref, cfg.Suppression.IgnoreFile)
	if err != nil {
		return nil, fmt.Errorf("suppression check against %s: %w", ref, err)
	}
	issues := make([]result.Issue, len(found))
	for i, f := range found {
		issues[i] = f.Issue()
	}
	logger.Infof("Suppression check against %s: %d new suppressions", ref, len(issues))
	return issues, nil
}

// applyFixes writes the suggested fixes to the source files. Finding paths
// are relative to the project root, which may differ from the working
// directory.
func applyFixes(targetPath string, results []result.Issue, logger *zap.SugaredLogger) error {
	root, err := workspace.ProjectRoot(targetPath)
	if err != nil {
		return err
	}
	changed, err := fixer.ApplyFixes(root, results)
	for _, file := range changed {
		logger.Infof("Applied fixes to %s", file)
	}
	return err
}

// applyBaselineAndDiff removes findings recorded in the baseline file and,
// in diff mode, findings outside the lines changed since the git reference.
// The analysis itself always covers the whole project.
func applyBaselineAndDiff(ctx context.Context, targetPath string, opts scanOptions, results []result.Issue, logger *zap.SugaredLogger) ([]result.Issue, error) {
	if opts.baseline != "" {
		known, err := baseline.Load(opts.baseline)
		if err != nil {
			return nil, err
		}
		var removed int
		results, removed = known.Filter(results)
		logger.Infof("Baseline %s suppressed %d known issues", opts.baseline, removed)
	}
	if opts.diffRef != "" {
		root, err := workspace.ProjectRoot(targetPath)
		if err != nil {
			return nil, err
		}
		changed, err := git.Diff(ctx, root, opts.diffRef)
		if err != nil {
			return nil, fmt.Errorf("diff mode: %w", err)
		}
		results = filterByDiff(results, changed)
		logger.Infof("Diff against %s: %d issues on changed lines", opts.diffRef, len(results))
	}
	return results, nil
}

// filterByDiff keeps findings on changed lines. Module-level findings are kept
// when go.mod or go.sum changed; findings without a line when their file changed.
func filterByDiff(results []result.Issue, changed git.ChangedLines) []result.Issue {
	out := make([]result.Issue, 0, len(results))
	for _, issue := range results {
		file := filepath.ToSlash(issue.Location.File)
		keep := false
		switch {
		case filepath.Base(file) == "go.mod" || filepath.Base(file) == "go.sum":
			dir := filepath.ToSlash(filepath.Dir(file))
			keep = changed.Touched(file) || changed.Touched(path.Join(dir, "go.mod")) || changed.Touched(path.Join(dir, "go.sum"))
		case issue.Location.Line <= 0:
			keep = changed.Touched(file)
		default:
			keep = changed.Contains(file, issue.Location.Line)
		}
		if keep {
			out = append(out, issue)
		}
	}
	return out
}

// getGitMetadata retrieves and logs Git metadata
func getGitMetadata(logger *zap.SugaredLogger) *report.GitMetadata {
	if gitMeta, err := git.GetGitMetadata(); err == nil {
		logger.Infof("Git repository root: %s", gitMeta.RepoRoot)
		if gitMeta.CommitHash != "" {
			logger.Infof("Latest commit: %s by %s", gitMeta.CommitShort, gitMeta.Author)
		}
		if gitMeta.IsDirty {
			logger.Warnf("Working directory has uncommitted changes")
		}

		// Convert to report.GitMetadata
		return &report.GitMetadata{
			RepoRoot:    gitMeta.RepoRoot,
			Branch:      gitMeta.Branch,
			CommitHash:  gitMeta.CommitHash,
			CommitShort: gitMeta.CommitShort,
			Author:      gitMeta.Author,
			Email:       gitMeta.Email,
			Message:     gitMeta.Message,
			Timestamp:   gitMeta.Timestamp,
			IsDirty:     gitMeta.IsDirty,
		}
	}
	return nil
}

// runDependencyAnalysis audits the dependencies of the module at targetPath.
// With reachability enabled, the module is loaded to build a call graph.
func runDependencyAnalysis(ctx context.Context, targetPath string, cfg *config.Config, logger *zap.SugaredLogger) ([]result.Issue, error) {
	goModPath := filepath.Join(targetPath, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return nil, fmt.Errorf("go.mod file not found in %s", targetPath)
	}
	opts := deps.OptionsFromConfig(cfg.Dependencies)
	if cfg.Dependencies.CheckVulnerabilities && cfg.Dependencies.CheckReachability {
		if ws, err := workspace.Load(ctx, targetPath, cfg); err != nil {
			logger.Warnf("Reachability analysis skipped: %v", err)
		} else if bundle, err := codessa.BuildFromWorkspace(ws); err != nil {
			logger.Warnf("Reachability analysis skipped: %v", err)
		} else {
			opts.Bundle = bundle
		}
	}
	reports, err := deps.ScanDependencies(ctx, goModPath, opts)
	if err != nil {
		if len(reports) == 0 {
			return nil, err
		}
		logger.Warnf("Dependency analysis incomplete: %v", err)
	}
	return deps.ReportIssues(reports, goModPath), nil
}

// runFullAnalysis performs the complete analysis workflow
func runFullAnalysis(ctx context.Context, targetPath, ignoreFile string, cfg *config.Config, severity string, logger *zap.SugaredLogger) ([]result.Issue, error) {
	if ignoreFile != "" {
		abs, err := filepath.Abs(ignoreFile)
		if err != nil {
			return nil, fmt.Errorf("resolve ignore file: %w", err)
		}
		cfg.Suppression.IgnoreFile = abs
		logger.Infof("Using ignore rules from: %s", abs)
	}

	// Run analysis; suppressions are applied by the engine
	runOpts := engine.Options{Rules: loadYAMLRules(cfg, logger), Cache: openCache(cfg, logger)}
	results, err := engine.RunWithOptions(ctx, targetPath, cfg, runOpts)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	if runOpts.Cache != nil {
		stats := runOpts.Cache.Stats()
		logger.Infof("Analysis cache %s: %d hits, %d misses", runOpts.Cache.Dir(), stats.Hits, stats.Misses)
	}

	return filterResults(results, severity, logger), nil
}

// openCache opens the analysis cache configured for the scan, or returns nil
// when caching is disabled or the directory cannot be used.
func openCache(cfg *config.Config, logger *zap.SugaredLogger) *cache.Cache {
	if !cfg.Scan.EnableCache {
		return nil
	}
	dir, err := cache.ResolveDir(cfg.Scan.CacheDir)
	if err == nil {
		var c *cache.Cache
		if c, err = cache.Open(dir); err == nil {
			return c
		}
	}
	logger.Warnf("Analysis cache disabled: %v", err)
	cfg.Scan.EnableCache = false
	return nil
}

// loadConfig loads configuration from file or default
func loadConfig(configFile string, logger *zap.SugaredLogger) (*config.Config, error) {
	if configFile != "" {
		cfg, err := config.LoadFromPath(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configFile, err)
		}
		logger.Infof("Loaded custom config from: %s", configFile)
		return cfg, nil
	}

	cfg, err := config.LoadDefaultPathPtr()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return cfg, nil
}

// loadYAMLRules compiles the YAML rules for one scan: the rules embedded in
// the binary, then the configured rule directories and files. A later rule
// replaces an earlier one with the same ID. Rule files that fail to load are
// reported as warnings so that the rest of the scan still runs.
func loadYAMLRules(cfg *config.Config, logger *zap.SugaredLogger) []*rules.Rule {
	var compiled []*yaml.CompiledRule
	add := func(source string, found []*yaml.CompiledRule, err error) {
		if err != nil {
			logger.Warnf("Failed to load YAML rules from %s: %v", source, err)
			return
		}
		logger.Infof("Loaded %d YAML rules from %s", len(found), source)
		compiled = append(compiled, found...)
	}
	found, err := yaml.LoadFromFS(assets.BuiltinRulesFS, "rules")
	add("built-in rules", found, err)
	for _, rulePath := range cfg.Rules.RulePaths {
		info, err := os.Stat(rulePath)
		switch {
		case err != nil:
			logger.Warnf("Rule path %s not found: %v", rulePath, err)
		case info.IsDir():
			found, err := yaml.CompileDir(rulePath)
			add(rulePath, found, err)
		default:
			found, err := yaml.CompileFile(rulePath)
			add(rulePath, found, err)
		}
	}
	for _, ruleFile := range cfg.Rules.RuleFiles {
		if _, err := os.Stat(ruleFile); err != nil {
			logger.Warnf("Rule file %s not found: %v", ruleFile, err)
			continue
		}
		found, err := yaml.CompileFile(ruleFile)
		add(ruleFile, found, err)
	}
	return yaml.Registrations(compiled)
}

// filterResults filters results by minimum severity
func filterResults(results []result.Issue, severity string, logger *zap.SugaredLogger) []result.Issue {
	// Filter by severity if specified
	if severity != "" {
		filteredResults := make([]result.Issue, 0)
		severityFilter := result.ParseSeverity(severity)
		for _, issue := range results {
			if issue.Severity.GreaterThanOrEqual(severityFilter) {
				filteredResults = append(filteredResults, issue)
			}
		}
		logger.Infof("Filtered to %d issues with severity >= %s", len(filteredResults), severity)
		results = filteredResults
	}

	return results
}

// generateReport creates and writes the analysis report
func generateReport(results []result.Issue, format, outPath string, gitMetadata *report.GitMetadata, logger *zap.SugaredLogger) error {
	if outPath == "" {
		outPath = filepath.Join("scan_reports", defaultOutputPath(format))
	}

	// Generate report
	if err := writeReport(results, format, outPath, gitMetadata); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	logger.Infof("Report generated: %s", outPath)
	return nil
}

// defaultOutputPath returns the default filename for a given report format.
func defaultOutputPath(format string) string {
	switch format {
	case "html":
		return "codex-report.html"
	case "markdown":
		return "codex-report.md"
	case "json":
		return "codex-report.json"
	case "agent":
		return "codex-report.agent.txt"
	case "github":
		return "codex-report.github.txt"
	case "gitlab":
		return "gl-code-quality-report.json"
	case "sarif":
		fallthrough
	default:
		return "codex-report.sarif"
	}
}

// writeReport writes the analysis results in the requested format to the given path.
func writeReport(results []result.Issue, format, outPath string, gitMetadata *report.GitMetadata) error {
	if outPath == "-" && format == "html" {
		return fmt.Errorf("stdout output is not supported for format: %s", format)
	}
	if outPath != "-" {
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	reportIssues := report.FromResults(results)

	switch format {
	case "html":
		return formats.WriteHTMLReport(reportIssues, outPath, gitMetadata)
	case "markdown":
		return formats.WriteMarkdownReport(reportIssues, outPath, gitMetadata)
	case "json":
		return formats.WriteJSONReport(reportIssues, outPath, gitMetadata)
	case "sarif":
		return formats.WriteSARIFReport(reportIssues, outPath, gitMetadata)
	case "agent":
		return formats.WriteAgentReport(reportIssues, outPath, gitMetadata)
	case "github":
		return formats.WriteGitHubReport(reportIssues, outPath, gitMetadata)
	case "gitlab":
		return formats.WriteGitLabReport(reportIssues, outPath, gitMetadata)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// printSummary prints a summary of the analysis results.
func printSummary(w io.Writer, results []result.Issue) {
	fmt.Fprintf(w, "Analysis complete. Found %d issues.\n", len(results))

	if len(results) > 0 {
		fmt.Fprintln(w, "\nIssues found:")
		for _, issue := range results {
			fmt.Fprintf(w, "  [%s] %s at %s:%d\n",
				issue.Severity.String(),
				issue.Title,
				issue.Location.File,
				issue.Location.Line)
			if issue.Description != "" {
				fmt.Fprintf(w, "      Description: %s\n", issue.Description)
			}
			if issue.Suggestion != "" {
				fmt.Fprintf(w, "      Remediation: %s\n", issue.Suggestion)
			}
			if len(issue.References) > 0 && issue.References[0] != "" {
				fmt.Fprintf(w, "      Reference:   %s\n", issue.References[0])
			}
		}
	}
}

// IssuesFoundError indicates a completed scan that failed the severity policy.
type IssuesFoundError struct{ Count int }

func (e *IssuesFoundError) Error() string { return fmt.Sprintf("scan found %d issues", e.Count) }

func normalizeTargetPath(path string) string {
	if strings.HasSuffix(filepath.ToSlash(path), "/...") {
		path = strings.TrimSuffix(filepath.ToSlash(path), "/...")
		if path == "" {
			return string(filepath.Separator)
		}
	}
	return path
}

func failingIssues(issues []result.Issue, strict bool, threshold string) int {
	count := 0
	for _, issue := range issues {
		if strict || (threshold != "" && issue.Severity.GreaterThanOrEqual(result.ParseSeverity(threshold))) {
			count++
		}
	}
	return count
}
