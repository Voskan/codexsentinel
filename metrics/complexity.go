// Package metrics provides static code quality metrics such as cyclomatic complexity.
package metrics

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ComplexityResult represents the cyclomatic complexity of a single function.
type ComplexityResult struct {
	Name       string // Function name
	File       string // File path
	Line       int    // Line number
	Complexity int    // Computed cyclomatic complexity
	Exported   bool   // Whether function is exported
	Category   string // Function category (high, medium, low)
	Risk       string // Risk assessment
}

// ComplexitySummary provides overall complexity statistics
type ComplexitySummary struct {
	TotalFunctions    int
	HighComplexity    int
	MediumComplexity  int
	LowComplexity     int
	AverageComplexity float64
	MaxComplexity     int
	RiskDistribution  map[string]int
}

// AnalyzeCyclomaticComplexity calculates complexity for all functions in given files.
func AnalyzeCyclomaticComplexity(files []string) ([]ComplexityResult, error) {
	var results []ComplexityResult
	fset := token.NewFileSet()

	for _, path := range files {
		node, err := parseGoFile(fset, path)
		if err != nil {
			continue
		}

		ast.Inspect(node, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			start := fset.Position(fn.Pos())
			score := computeComplexity(fn.Body)
			
			// Determine category and risk
			category, risk := categorizeComplexity(score)

			results = append(results, ComplexityResult{
				Name:       fn.Name.Name,
				File:       filepath.ToSlash(start.Filename),
				Line:       start.Line,
				Complexity: score,
				Exported:   fn.Name.IsExported(),
				Category:   category,
				Risk:       risk,
			})

			return false
		})
	}

	// Sort by complexity (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Complexity > results[j].Complexity
	})

	return results, nil
}

// categorizeComplexity determines the category and risk level based on complexity
func categorizeComplexity(complexity int) (category, risk string) {
	switch {
	case complexity >= 15:
		return "high", "Critical - Very difficult to maintain and test"
	case complexity >= 10:
		return "medium", "High - Consider refactoring"
	case complexity >= 5:
		return "low", "Medium - Monitor for growth"
	default:
		return "simple", "Low - Good complexity level"
	}
}

// ComputeComplexitySummary calculates overall complexity statistics
func ComputeComplexitySummary(results []ComplexityResult) ComplexitySummary {
	if len(results) == 0 {
		return ComplexitySummary{}
	}

	summary := ComplexitySummary{
		TotalFunctions: len(results),
		RiskDistribution: make(map[string]int),
	}

	totalComplexity := 0
	for _, result := range results {
		totalComplexity += result.Complexity
		
		if result.Complexity > summary.MaxComplexity {
			summary.MaxComplexity = result.Complexity
		}
		
		switch result.Category {
		case "high":
			summary.HighComplexity++
		case "medium":
			summary.MediumComplexity++
		case "low":
			summary.LowComplexity++
		}
		
		summary.RiskDistribution[result.Risk]++
	}
	
	summary.AverageComplexity = float64(totalComplexity) / float64(len(results))
	
	return summary
}

// computeComplexity calculates the cyclomatic complexity of a function body.
func computeComplexity(body *ast.BlockStmt) int {
	score := 1 // Start with 1 for the default path

	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause,
			*ast.SelectStmt, *ast.CommClause:
			score++
		case *ast.BinaryExpr:
			if stmt.Op.String() == "&&" || stmt.Op.String() == "||" {
				score++
			}
		case *ast.SwitchStmt, *ast.TypeSwitchStmt:
			// Cases are counted via CaseClause
		}
		return true
	})

	return score
}

// parseGoFile parses a Go source file from disk.
func parseGoFile(fset *token.FileSet, path string) (*ast.File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	node, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", path, err)
	}
	return node, nil
}

// GenerateComplexityReport creates a formatted complexity report
func GenerateComplexityReport(results []ComplexityResult) string {
	if len(results) == 0 {
		return "No functions found for complexity analysis."
	}

	summary := ComputeComplexitySummary(results)
	
	var report strings.Builder
	
	// Header
	report.WriteString("📊 Cyclomatic Complexity Analysis Report\n")
	report.WriteString("=====================================\n\n")
	
	// Summary statistics
	report.WriteString("📈 Summary Statistics:\n")
	report.WriteString(fmt.Sprintf("   • Total Functions: %d\n", summary.TotalFunctions))
	report.WriteString(fmt.Sprintf("   • Average Complexity: %.2f\n", summary.AverageComplexity))
	report.WriteString(fmt.Sprintf("   • Maximum Complexity: %d\n", summary.MaxComplexity))
	report.WriteString(fmt.Sprintf("   • High Complexity (≥10): %d\n", summary.HighComplexity))
	report.WriteString(fmt.Sprintf("   • Medium Complexity (5-9): %d\n", summary.MediumComplexity))
	report.WriteString(fmt.Sprintf("   • Low Complexity (<5): %d\n\n", summary.LowComplexity))
	
	// Risk distribution
	report.WriteString("⚠️  Risk Distribution:\n")
	for risk, count := range summary.RiskDistribution {
		report.WriteString(fmt.Sprintf("   • %s: %d functions\n", risk, count))
	}
	report.WriteString("\n")
	
	// Top complex functions
	report.WriteString("🔝 Top 10 Most Complex Functions:\n")
	for i, result := range results[:min(10, len(results))] {
		icon := getComplexityIcon(result.Complexity)
		report.WriteString(fmt.Sprintf("   %d. %s %s (%s:%d) - Complexity: %d\n", 
			i+1, icon, result.Name, result.File, result.Line, result.Complexity))
	}
	
	return report.String()
}

// getComplexityIcon returns an appropriate icon based on complexity
func getComplexityIcon(complexity int) string {
	switch {
	case complexity >= 15:
		return "🚨"
	case complexity >= 10:
		return "⚠️"
	case complexity >= 5:
		return "⚡"
	default:
		return "✅"
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
