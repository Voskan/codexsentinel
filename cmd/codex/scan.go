package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go/token"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules/yaml"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/deps"
	"github.com/Voskan/codexsentinel/internal/fsutil"
	"github.com/Voskan/codexsentinel/internal/git"
	"github.com/Voskan/codexsentinel/internal/ignore"
	"github.com/Voskan/codexsentinel/internal/logx"
	"github.com/Voskan/codexsentinel/report"
	"github.com/Voskan/codexsentinel/report/formats"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewScanCmd returns the `scan` command that analyzes the target source code.
func NewScanCmd() *cobra.Command {
	var (
		path       string
		format     string
		outPath    string
		strict     bool
		ignoreFile string
		depsOnly   bool
		configFile string
		severity   string
		exitCode   int
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run static analysis on the target source code",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(path, args, format, outPath, strict, ignoreFile, depsOnly, configFile, severity, exitCode)
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", ".", "Target directory or file to scan")
	cmd.Flags().StringVarP(&format, "format", "f", "sarif", "Output report format: sarif, html, markdown, json")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Path to write the output report to")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit with code 1 if issues are found")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", ".codexsentinel.ignore", "Path to ignore file")
	cmd.Flags().BoolVar(&depsOnly, "deps", false, "Run dependency analysis only")
	cmd.Flags().StringVar(&configFile, "config", "", "Path to a custom config file")
	cmd.Flags().StringVar(&severity, "severity", "", "Filter issues by severity (low, medium, high, critical)")

	return cmd
}

// runScan handles the main scan logic
func runScan(path string, args []string, format, outPath string, strict bool, ignoreFile string, depsOnly bool, configFile, severity string, exitCode int) error {
	ctx := context.Background()

	// Use path from args if provided, otherwise use flag
	targetPath := path
	if len(args) > 0 {
		targetPath = args[0]
	}

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

	if depsOnly {
		// Run only dependency analysis
		logger.Infof("Running dependency analysis only")
		results, err = runDependencyAnalysis(targetPath)
		if err != nil {
			return fmt.Errorf("dependency analysis failed: %w", err)
		}
	} else {
		// Run full analysis
		results, err = runFullAnalysis(ctx, targetPath, ignoreFile, configFile, severity, logger)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
	}

	logger.Infof("Analysis completed, found %d issues", len(results))

	// Generate report
	if err := generateReport(results, format, outPath, gitMetadata, logger); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Display result summary
	printSummary(results)

	// Exit code control
	if strict && len(results) > 0 {
		exitCode = 1
	}
	os.Exit(exitCode)
	return nil
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

// runDependencyAnalysis performs dependency analysis and returns issues
func runDependencyAnalysis(targetPath string) ([]result.Issue, error) {
	var issues []result.Issue

	// Find go.mod file
	goModPath := filepath.Join(targetPath, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("go.mod file not found in %s", targetPath)
	}

	// Default license lists
	allowLicenses := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}
	denyLicenses := []string{"AGPL-3.0", "GPL-3.0", "BSL-1.1"}

	// Run dependency analysis
	reports, err := deps.ScanDependencies(goModPath, allowLicenses, denyLicenses)
	if err != nil {
		return nil, fmt.Errorf("dependency analysis failed: %w", err)
	}

	// Convert dependency reports to issues
	for _, report := range reports {
		// License issues
		if report.LicenseStatus == "DENIED" {
			issues = append(issues, result.Issue{
				ID:          "license-denied",
				Title:       "Denied License Detected",
				Description: fmt.Sprintf("Module %s uses denied license: %s", report.Module, report.License),
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
				Category:    "license",
				Suggestion:  "Consider using a different dependency with an allowed license",
			})
		}

		// Vulnerability issues
		for _, vuln := range report.Vulnerabilities {
			issues = append(issues, result.Issue{
				ID:          "dependency-vulnerability",
				Title:       "Vulnerable Dependency",
				Description: fmt.Sprintf("Module %s@%s has vulnerability: %s\nDetails: %s", report.Module, report.Version, vuln.ID, vuln.Details),
				Severity:    result.SeverityHigh,
				Location:    result.NewLocationFromPos(token.Position{Filename: goModPath}, "", ""),
				Category:    "security",
				Suggestion:  fmt.Sprintf("Update to a fixed version: %s or apply security patches", vuln.FixedVersion),
				References:  []string{vuln.Reference},
			})
		}

		// Entropy findings (potential secrets)
		for _, entropy := range report.SuspiciousFiles {
			issues = append(issues, result.Issue{
				ID:          "high-entropy-string",
				Title:       "High Entropy String Detected",
				Description: fmt.Sprintf("Potential secret found in %s at line %d", entropy.File, entropy.Line),
				Severity:    result.SeverityMedium,
				Location:    result.NewLocationFromPos(token.Position{Filename: entropy.File, Line: entropy.Line}, "", ""),
				Category:    "security",
				Suggestion:  "Review and remove hardcoded secrets from the codebase",
			})
		}
	}

	return issues, nil
}

// runFullAnalysis performs the complete analysis workflow
func runFullAnalysis(ctx context.Context, targetPath, ignoreFile, configFile, severity string, logger *zap.SugaredLogger) ([]result.Issue, error) {
	// Use fsutil for safe file walking
	fileOpts := fsutil.WalkOptions{
		RootDir:            targetPath,
		AllowedExtensions:  []string{".go"},
		MaxFileSizeBytes:   10 * 1024 * 1024, // 10MB limit
		FollowSymlinks:     false,
		IncludeHiddenFiles: false,
		ExcludedPaths:      []string{"vendor", "node_modules", ".git"},
	}

	files, err := fsutil.Walk(fileOpts)
	if err != nil {
		logger.Warnf("Failed to walk files: %v", err)
	} else {
		logger.Infof("Found %d Go files to analyze", len(files))
	}

	// Load ignore rules if specified
	ignoreManager := loadIgnoreManager(ignoreFile, logger)

	// Load config
	cfg, err := loadConfig(configFile, logger)
	if err != nil {
		return nil, err
	}

	// Load YAML rules
	loadYAMLRules(cfg, logger)

	// Run analysis
	results, err := engine.Run(ctx, targetPath, cfg)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	// Filter results
	results = filterResults(results, ignoreManager, severity, logger)

	return results, nil
}

// loadIgnoreManager loads ignore rules from file
func loadIgnoreManager(ignoreFile string, logger *zap.SugaredLogger) *ignore.Manager {
	if ignoreFile == "" {
		return nil
	}

	ignoreManager := ignore.NewManager()
	if err := ignoreManager.LoadFile(ignoreFile); err != nil {
		logger.Warnf("Failed to load ignore file: %v", err)
		return nil
	}

	logger.Infof("Loaded ignore rules from: %s", ignoreFile)
	return ignoreManager
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

// loadYAMLRules loads YAML rules from directories
func loadYAMLRules(cfg *config.Config, logger *zap.SugaredLogger) {
	// Load YAML rules from assets/rules directory
	yamlRulesDir := "assets/rules"
	if _, err := os.Stat(yamlRulesDir); err == nil {
		if err := yaml.LoadFromDir(yamlRulesDir); err != nil {
			logger.Warnf("Failed to load YAML rules from %s: %v", yamlRulesDir, err)
		} else {
			logger.Infof("Loaded YAML rules from %s", yamlRulesDir)
		}
	}

	// Load YAML rules from config rule paths
	for _, rulePath := range cfg.Rules.RulePaths {
		if _, err := os.Stat(rulePath); err == nil {
			if err := yaml.LoadFromDir(rulePath); err != nil {
				logger.Warnf("Failed to load YAML rules from %s: %v", rulePath, err)
			} else {
				logger.Infof("Loaded YAML rules from %s", rulePath)
			}
		}
	}
}

// filterResults filters results based on ignore rules and severity
func filterResults(results []result.Issue, ignoreManager *ignore.Manager, severity string, logger *zap.SugaredLogger) []result.Issue {
	// Filter out ignored issues
	if ignoreManager != nil {
		filteredResults := make([]result.Issue, 0)
		ignoredCount := 0
		for _, issue := range results {
			if !ignoreManager.IsIgnored(issue.Location.File, issue.Location.Line, issue.ID) {
				filteredResults = append(filteredResults, issue)
			} else {
				ignoredCount++
			}
		}
		if ignoredCount > 0 {
			logger.Infof("Ignored %d issues based on ignore rules", ignoredCount)
		}
		results = filteredResults
	}

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
	// Determine output path
	reportDir := "scan_reports"
	if _, err := os.Stat(reportDir); os.IsNotExist(err) {
		if err := os.Mkdir(reportDir, 0755); err != nil {
			return fmt.Errorf("failed to create report directory: %w", err)
		}
	}
	if outPath == "" {
		outPath = filepath.Join(reportDir, defaultOutputPath(format))
	} else {
		outPath = filepath.Join(reportDir, filepath.Base(outPath))
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
	case "sarif":
		fallthrough
	default:
		return "codex-report.sarif"
	}
}

// writeReport writes the analysis results in the requested format to the given path.
func writeReport(results []result.Issue, format, outPath string, gitMetadata *report.GitMetadata) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Convert result.Issue to report.Issue
	reportIssues := make([]report.Issue, len(results))
	for i, issue := range results {
		reportIssues[i] = report.Issue{
			RuleID:      issue.ID,
			Title:       issue.Title,
			Description: issue.Description,
			Severity:    report.SeverityLevel(issue.Severity.String()),
			File:        issue.Location.File,
			Line:        issue.Location.Line,
			Suggestion:  issue.Suggestion,
		}
	}

	switch format {
	case "html":
		return formats.WriteHTMLReport(reportIssues, outPath, gitMetadata)
	case "markdown":
		return formats.WriteMarkdownReport(reportIssues, outPath, gitMetadata)
	case "json":
		return formats.WriteJSONReport(reportIssues, outPath, gitMetadata)
	case "sarif":
		return formats.WriteSARIFReport(reportIssues, outPath, gitMetadata)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// printSummary prints a summary of the analysis results.
func printSummary(results []result.Issue) {
	fmt.Printf("Analysis complete. Found %d issues.\n", len(results))

	if len(results) > 0 {
		fmt.Println("\nIssues found:")
		for _, issue := range results {
			fmt.Printf("  [%s] %s at %s:%d\n",
				issue.Severity.String(),
				issue.Title,
				issue.Location.File,
				issue.Location.Line)
			if issue.Description != "" {
				fmt.Printf("      Description: %s\n", issue.Description)
			}
			if issue.Suggestion != "" {
				fmt.Printf("      Remediation: %s\n", issue.Suggestion)
			}
			if len(issue.References) > 0 && issue.References[0] != "" {
				fmt.Printf("      Reference:   %s\n", issue.References[0])
			}
		}
	}
}
