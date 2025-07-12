package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/internal/fsutil"
	"github.com/Voskan/codexsentinel/internal/git"
	"github.com/Voskan/codexsentinel/internal/ignore"
	"github.com/Voskan/codexsentinel/internal/logx"
	"github.com/Voskan/codexsentinel/report"
	"github.com/Voskan/codexsentinel/report/formats"
	"github.com/spf13/cobra"
)

// NewScanCmd returns the `scan` command that analyzes the target source code.
func NewScanCmd() *cobra.Command {
	var (
		path       string
		format     string
		outPath    string
		strict     bool
		ignoreFile string
		exitCode   int
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run static analysis on the target source code",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			var gitMetadata *report.GitMetadata
			if gitMeta, err := git.GetGitMetadata(); err == nil {
				logger.Infof("Git repository root: %s", gitMeta.RepoRoot)
				if gitMeta.CommitHash != "" {
					logger.Infof("Latest commit: %s by %s", gitMeta.CommitShort, gitMeta.Author)
				}
				if gitMeta.IsDirty {
					logger.Warnf("Working directory has uncommitted changes")
				}
				
				// Convert to report.GitMetadata
				gitMetadata = &report.GitMetadata{
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

			// Use fsutil for safe file walking
			fileOpts := fsutil.WalkOptions{
				RootDir:           targetPath,
				AllowedExtensions: []string{".go"},
				MaxFileSizeBytes:  10 * 1024 * 1024, // 10MB limit
				FollowSymlinks:    false,
				IncludeHiddenFiles: false,
				ExcludedPaths:     []string{"vendor", "node_modules", ".git"},
			}

			files, err := fsutil.Walk(fileOpts)
			if err != nil {
				logger.Warnf("Failed to walk files: %v", err)
			} else {
				logger.Infof("Found %d Go files to analyze", len(files))
			}

			// Load ignore rules if specified
			var ignoreManager *ignore.Manager
			if ignoreFile != "" {
				ignoreManager = ignore.NewManager()
				if err := ignoreManager.LoadFile(ignoreFile); err != nil {
					logger.Warnf("Failed to load ignore file: %v", err)
				} else {
					logger.Infof("Loaded ignore rules from: %s", ignoreFile)
				}
			}

			// Load config
			cfg, err := config.LoadDefaultPath()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Run analysis
			results, err := engine.Run(ctx, targetPath, cfg)
			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}

			logger.Infof("Analysis completed, found %d issues", len(results))

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

			// Display result summary
			printSummary(results)

			// Exit code control
			if strict && len(results) > 0 {
				exitCode = 1
			}
			os.Exit(exitCode)
			return nil
		},
	}

	cmd.Flags().StringVarP(&path, "path", "p", ".", "Target directory or file to scan")
	cmd.Flags().StringVarP(&format, "format", "f", "sarif", "Output report format: sarif, html, markdown, json")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "Path to write the output report to")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit with code 1 if issues are found")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", ".codexsentinel.ignore", "Path to ignore file")

	return cmd
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
		}
	}
}
