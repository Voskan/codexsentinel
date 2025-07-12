package engine

import (
	"context"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/metrics"
)

// runMetricsAnalysis performs comprehensive code quality metrics analysis
func runMetricsAnalysis(ctx context.Context, proj *analyzer.AnalyzerContext) ([]*result.Issue, error) {
	var issues []*result.Issue

	// For single files, analyze the file directly
	if proj.Filename != "" && !isDirectory(proj.Filename) {
		fileIssues, err := analyzeSingleFileMetrics(proj.Filename)
		if err != nil {
			return nil, fmt.Errorf("metrics analysis failed: %w", err)
		}
		issues = append(issues, fileIssues...)
		return issues, nil
	}

	// For directories, analyze all Go files
	dir := filepath.Dir(proj.Filename)
	if proj.Filename == "" {
		dir = "."
	}

	// Find all Go files
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".go" {
			// Skip test files unless explicitly requested
			if !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Analyze complexity
	complexityIssues, err := analyzeComplexity(files)
	if err != nil {
		return nil, fmt.Errorf("complexity analysis failed: %w", err)
	}
	issues = append(issues, complexityIssues...)

	// Analyze function sizes
	sizeIssues, err := analyzeFunctionSizes(files)
	if err != nil {
		return nil, fmt.Errorf("function size analysis failed: %w", err)
	}
	issues = append(issues, sizeIssues...)

	// Analyze dead code
	deadCodeIssues, err := analyzeDeadCode(dir)
	if err != nil {
		return nil, fmt.Errorf("dead code analysis failed: %w", err)
	}
	issues = append(issues, deadCodeIssues...)

	// Analyze code duplication
	duplicationIssues, err := analyzeDuplication(files)
	if err != nil {
		return nil, fmt.Errorf("duplication analysis failed: %w", err)
	}
	issues = append(issues, duplicationIssues...)

	// Analyze global variables
	globalIssues, err := analyzeGlobals(dir)
	if err != nil {
		return nil, fmt.Errorf("global variables analysis failed: %w", err)
	}
	issues = append(issues, globalIssues...)

	return issues, nil
}

// analyzeSingleFileMetrics analyzes metrics for a single file
func analyzeSingleFileMetrics(filename string) ([]*result.Issue, error) {
	var issues []*result.Issue

			// Analyze complexity
		complexityResults, err := metrics.AnalyzeCyclomaticComplexity([]string{filename})
		if err == nil {
			for _, complexityResult := range complexityResults {
				if complexityResult.Complexity > 10 { // Threshold
					issues = append(issues, &result.Issue{
						ID:          "high-complexity",
						Title:       "High Cyclomatic Complexity",
						Description: fmt.Sprintf("Function %s has complexity %d (threshold: 10)", complexityResult.Name, complexityResult.Complexity),
						Severity:    result.SeverityMedium,
						Location:    result.NewLocationFromPos(token.Position{Filename: complexityResult.File, Line: complexityResult.Line}, "", ""),
						Category:    "metrics",
						Suggestion:  "Consider breaking down the function into smaller functions",
					})
				}
			}
		}

		// Analyze function sizes
		sizeResults, err := metrics.AnalyzeFunctionSizes([]string{filename})
		if err == nil {
			for _, sizeResult := range sizeResults {
				if sizeResult.LOC > 50 { // Threshold
					issues = append(issues, &result.Issue{
						ID:          "large-function",
						Title:       "Large Function",
						Description: fmt.Sprintf("Function %s has %d lines of code (threshold: 50)", sizeResult.Name, sizeResult.LOC),
						Severity:    result.SeverityLow,
						Location:    result.NewLocationFromPos(token.Position{Filename: sizeResult.File, Line: sizeResult.Line}, "", ""),
						Category:    "metrics",
						Suggestion:  "Consider breaking down the function into smaller functions",
					})
				}
			}
		}

	return issues, nil
}

// analyzeComplexity analyzes cyclomatic complexity
func analyzeComplexity(files []string) ([]*result.Issue, error) {
	var issues []*result.Issue

	complexityResults, err := metrics.AnalyzeCyclomaticComplexity(files)
	if err != nil {
		return nil, err
	}

	for _, complexityResult := range complexityResults {
		if complexityResult.Complexity > 10 {
			issues = append(issues, &result.Issue{
				ID:          "high-complexity",
				Title:       "High Cyclomatic Complexity",
				Description: fmt.Sprintf("Function %s has complexity %d (threshold: 10)", complexityResult.Name, complexityResult.Complexity),
				Severity:    result.SeverityMedium,
				Location:    result.NewLocationFromPos(token.Position{Filename: complexityResult.File, Line: complexityResult.Line}, "", ""),
				Category:    "metrics",
				Suggestion:  "Consider breaking down the function into smaller functions",
			})
		}
	}

	return issues, nil
}

// analyzeFunctionSizes analyzes function sizes
func analyzeFunctionSizes(files []string) ([]*result.Issue, error) {
	var issues []*result.Issue

	sizeResults, err := metrics.AnalyzeFunctionSizes(files)
	if err != nil {
		return nil, err
	}

	for _, sizeResult := range sizeResults {
		if sizeResult.LOC > 50 {
			issues = append(issues, &result.Issue{
				ID:          "large-function",
				Title:       "Large Function",
				Description: fmt.Sprintf("Function %s has %d lines of code (threshold: 50)", sizeResult.Name, sizeResult.LOC),
				Severity:    result.SeverityLow,
				Location:    result.NewLocationFromPos(token.Position{Filename: sizeResult.File, Line: sizeResult.Line}, "", ""),
				Category:    "metrics",
				Suggestion:  "Consider breaking down the function into smaller functions",
			})
		}
	}

	return issues, nil
}

// analyzeDeadCode analyzes dead code
func analyzeDeadCode(dir string) ([]*result.Issue, error) {
	var issues []*result.Issue

	deadCodeResults, err := metrics.AnalyzeDeadCode(dir)
	if err != nil {
		return nil, err
	}

	for _, deadCodeResult := range deadCodeResults {
		// Parse position string to get file and line
		parts := strings.Split(deadCodeResult.Pos, ":")
		if len(parts) >= 2 {
			line, _ := strconv.Atoi(parts[1])
			issues = append(issues, &result.Issue{
				ID:          "dead-code",
				Title:       "Dead Code Detected",
				Description: fmt.Sprintf("Function %s is never used", deadCodeResult.Name),
				Severity:    result.SeverityLow,
				Location:    result.NewLocationFromPos(token.Position{Filename: parts[0], Line: line}, "", ""),
				Category:    "metrics",
				Suggestion:  "Consider removing unused functions to improve code maintainability",
			})
		}
	}

	return issues, nil
}

// analyzeDuplication analyzes code duplication
func analyzeDuplication(files []string) ([]*result.Issue, error) {
	var issues []*result.Issue

	duplicationResults, err := metrics.AnalyzeDuplicatedFunctions(files)
	if err != nil {
		return nil, err
	}

	for _, duplicationResult := range duplicationResults {
		if len(duplicationResult.Funcs) > 1 {
			// Create issue for each duplicate function
			for _, fn := range duplicationResult.Funcs {
				issues = append(issues, &result.Issue{
					ID:          "code-duplication",
					Title:       "Code Duplication Detected",
					Description: fmt.Sprintf("Function %s has duplicate implementation found in %d locations", fn.Name, len(duplicationResult.Funcs)),
					Severity:    result.SeverityMedium,
					Location:    result.NewLocationFromPos(token.Position{Filename: fn.File, Line: fn.Line}, "", ""),
					Category:    "metrics",
					Suggestion:  "Consider extracting common functionality into a shared function",
				})
			}
		}
	}

	return issues, nil
}

// analyzeGlobals analyzes global variables
func analyzeGlobals(dir string) ([]*result.Issue, error) {
	var issues []*result.Issue

	globalResults, err := metrics.AnalyzeGlobals(dir)
	if err != nil {
		return nil, err
	}

	for _, global := range globalResults {
		issues = append(issues, &result.Issue{
			ID:          "global-variable",
			Title:       "Global Variable Detected",
			Description: fmt.Sprintf("Global %s %s found in package %s", global.Kind, global.Name, global.PkgPath),
			Severity:    result.SeverityLow,
			Location:    result.NewLocationFromPos(token.Position{Filename: global.File, Line: global.Line}, "", ""),
			Category:    "metrics",
			Suggestion:  "Consider using dependency injection or local variables instead of globals",
		})
	}

	return issues, nil
} 