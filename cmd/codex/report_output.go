package codex

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/config"
	"github.com/Voskan/codexsentinel/v2/report"
	"github.com/Voskan/codexsentinel/v2/report/formats"
	"go.uber.org/zap"
)

// reportOutput is one report to write: a format and a file, or "-" for stdout.
type reportOutput struct{ format, path string }

// reportOutputs returns the reports to write: the --format flag, or every
// format in report.formats. Without --out, each report goes to its default
// file name in report.output_dir; github workflow commands go to stdout.
func reportOutputs(opts scanOptions, cfg *config.Config) ([]reportOutput, error) {
	formatList := []string{opts.format}
	if !opts.formatSet && len(cfg.Report.Formats) > 0 {
		formatList = nil
		for _, f := range cfg.Report.Formats {
			if !slices.Contains(formatList, f) {
				formatList = append(formatList, f)
			}
		}
	}
	if opts.outPath != "" && len(formatList) > 1 {
		return nil, fmt.Errorf("--out needs a single report format, but report.formats lists %s; pass --format", strings.Join(formatList, ", "))
	}
	dir := cfg.Report.OutputDir
	if dir == "" {
		dir = "scan_reports"
	}
	outputs := make([]reportOutput, 0, len(formatList))
	for _, format := range formatList {
		if !slices.Contains(reportFormats, format) {
			return nil, fmt.Errorf("unsupported format: %s", format)
		}
		path := opts.outPath
		switch {
		case path == "" && format == "github":
			path = "-" // workflow commands only work on stdout
		case path == "":
			path = filepath.Join(dir, defaultOutputPath(format))
		}
		if path == "-" && format == "html" {
			return nil, fmt.Errorf("stdout output is not supported for format: %s", format)
		}
		outputs = append(outputs, reportOutput{format, path})
	}
	return outputs, nil
}

// reportFormats lists the supported report formats.
var reportFormats = []string{"sarif", "json", "html", "markdown", "agent", "github", "gitlab"}

// publishResults writes the reports, prints the summary (to stderr when a
// report goes to stdout) and appends the job summary.
func publishResults(all []result.Issue, outputs []reportOutput, githubSummary string, gitMetadata *report.GitMetadata, logger *zap.SugaredLogger) error {
	summaryOutput := io.Writer(os.Stdout)
	github := false
	for _, out := range outputs {
		if err := generateReport(all, out.format, out.path, gitMetadata, logger); err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}
		if out.path == "-" {
			summaryOutput = os.Stderr
		}
		github = github || out.format == "github"
	}
	printSummary(summaryOutput, all)
	if err := writeGitHubSummary(githubSummary, github, all); err != nil {
		return fmt.Errorf("failed to write job summary: %w", err)
	}
	return nil
}

// writeGitHubSummary appends the Markdown job summary to the given file, or
// to $GITHUB_STEP_SUMMARY when a github report is written.
func writeGitHubSummary(path string, github bool, results []result.Issue) error {
	if path == "" && github {
		path = os.Getenv("GITHUB_STEP_SUMMARY")
	}
	if path == "" {
		return nil
	}
	return formats.AppendGitHubStepSummary(report.FromResults(results), path)
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
	if outPath != "-" && filepath.Dir(outPath) != "." {
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
