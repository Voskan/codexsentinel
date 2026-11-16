// Package metrics provides static code quality metrics such as cyclomatic complexity.
package metrics

import (
	"fmt"
	"go/ast"
	"go/token"
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

// AnalyzeComplexity calculates the cyclomatic complexity of every function
// declared in files.
func AnalyzeComplexity(fset *token.FileSet, files []*ast.File) []ComplexityResult {
	var results []ComplexityResult
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Pos())
			score := computeComplexity(fn.Body)
			category, risk := categorizeComplexity(score)
			results = append(results, ComplexityResult{
				Name:       funcName(fn),
				File:       start.Filename,
				Line:       start.Line,
				Complexity: score,
				Exported:   fn.Name.IsExported(),
				Category:   category,
				Risk:       risk,
			})
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Complexity > results[j].Complexity
	})
	return results
}

// funcName returns the qualified name of a function declaration (Type.Method for methods).
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.ParenExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fn.Name.Name
		}
		return fn.Name.Name
	}
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
		TotalFunctions:   len(results),
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
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			score++
		case *ast.CaseClause:
			if stmt.List != nil {
				score++
			}
		case *ast.CommClause:
			if stmt.Comm != nil {
				score++
			}
		case *ast.BinaryExpr:
			if stmt.Op == token.LAND || stmt.Op == token.LOR {
				score++
			}
		}
		return true
	})

	return score
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
