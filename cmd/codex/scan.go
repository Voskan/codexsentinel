package codex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/internal/ignore"
	"github.com/Voskan/codexsentinel/report"
	"github.com/Voskan/codexsentinel/report/formats"
	"github.com/spf13/cobra"
)

// NewScanCmd returns the `scan` command that analyzes the target source code.
func NewScanCmd() *cobra.Command {
	var (
		path     string
		format   string
		outPath  string
		strict   bool
		ignoreFile string
		exitCode int
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

			// Load ignore rules if specified
			var ignoreManager *ignore.Manager
			if ignoreFile != "" {
				ignoreManager = ignore.NewManager()
				if err := ignoreManager.LoadFile(ignoreFile); err != nil {
					return fmt.Errorf("failed to load ignore file: %w", err)
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

			// Filter out ignored issues
			if ignoreManager != nil {
				filteredResults := make([]result.Issue, 0)
				for _, issue := range results {
					if !ignoreManager.IsIgnored(issue.Location.File, issue.Location.Line, issue.ID) {
						filteredResults = append(filteredResults, issue)
					}
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
			if err := writeReport(results, format, outPath); err != nil {
				return fmt.Errorf("failed to write report: %w", err)
			}

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
func writeReport(results []result.Issue, format, outPath string) error {
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
		return formats.WriteHTMLReport(reportIssues, outPath)
	case "markdown":
		return formats.WriteMarkdownReport(reportIssues, outPath)
	case "json":
		return formats.WriteJSONReport(reportIssues, outPath)
	case "sarif":
		return formats.WriteSARIFReport(reportIssues, outPath)
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
