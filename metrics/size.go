// Package metrics provides analysis of code quality metrics such as function and file size.
package metrics

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
)

// FunctionSize stores metrics about a function's line length.
type FunctionSize struct {
	Name     string // Function name
	LOC      int    // Lines of code
	File     string // File path
	Line     int    // Line number where the function starts
	Exported bool   // Whether function is exported
	Category string // Size category (large, medium, small)
	Risk     string // Risk assessment
}

// FileSize stores metrics about a file's total lines of code.
type FileSize struct {
	File     string // File path
	LOC      int    // Total lines of code
	Category string // Size category
	Risk     string // Risk assessment
}

// SizeSummary provides overall size statistics
type SizeSummary struct {
	TotalFunctions   int
	LargeFunctions   int
	MediumFunctions  int
	SmallFunctions   int
	AverageLOC       float64
	MaxLOC           int
	TotalFiles       int
	LargeFiles       int
	MediumFiles      int
	SmallFiles       int
	RiskDistribution map[string]int
}

// AnalyzeFunctionSizes returns the body length in lines of every function declared in files.
func AnalyzeFunctionSizes(fset *token.FileSet, files []*ast.File) []FunctionSize {
	var result []FunctionSize
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			loc := bodyLines(fset, fn.Body)
			category, risk := categorizeFunctionSize(loc)
			start := fset.Position(fn.Pos())
			result = append(result, FunctionSize{
				Name:     funcName(fn),
				LOC:      loc,
				File:     start.Filename,
				Line:     start.Line,
				Exported: fn.Name.IsExported(),
				Category: category,
				Risk:     risk,
			})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].LOC > result[j].LOC
	})
	return result
}

// bodyLines returns the number of lines spanned by a function body.
func bodyLines(fset *token.FileSet, body *ast.BlockStmt) int {
	return fset.Position(body.End()).Line - fset.Position(body.Pos()).Line + 1
}

// categorizeFunctionSize determines the category and risk level based on function size
func categorizeFunctionSize(loc int) (category, risk string) {
	switch {
	case loc >= 100:
		return "large", "Critical - Very difficult to maintain and understand"
	case loc >= 50:
		return "medium", "High - Consider breaking down into smaller functions"
	case loc >= 20:
		return "small", "Medium - Monitor for growth"
	default:
		return "tiny", "Low - Good function size"
	}
}

// AnalyzeFileSizes returns the line count of each parsed file.
func AnalyzeFileSizes(fset *token.FileSet, files []*ast.File) []FileSize {
	var result []FileSize
	for _, file := range files {
		tf := fset.File(file.Pos())
		if tf == nil {
			continue
		}
		lines := tf.LineCount()
		category, risk := categorizeFileSize(lines)
		result = append(result, FileSize{
			File:     tf.Name(),
			LOC:      lines,
			Category: category,
			Risk:     risk,
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].LOC > result[j].LOC
	})
	return result
}

// categorizeFileSize determines the category and risk level based on file size
func categorizeFileSize(loc int) (category, risk string) {
	switch {
	case loc >= 1000:
		return "large", "Critical - Very difficult to navigate and maintain"
	case loc >= 500:
		return "medium", "High - Consider splitting into smaller files"
	case loc >= 200:
		return "small", "Medium - Monitor for growth"
	default:
		return "tiny", "Low - Good file size"
	}
}

// ComputeSizeSummary calculates overall size statistics
func ComputeSizeSummary(functions []FunctionSize, files []FileSize) SizeSummary {
	summary := SizeSummary{
		RiskDistribution: make(map[string]int),
	}

	// Function statistics
	summary.TotalFunctions = len(functions)
	totalLOC := 0
	for _, fn := range functions {
		totalLOC += fn.LOC

		if fn.LOC > summary.MaxLOC {
			summary.MaxLOC = fn.LOC
		}

		switch fn.Category {
		case "large":
			summary.LargeFunctions++
		case "medium":
			summary.MediumFunctions++
		case "small":
			summary.SmallFunctions++
		}

		summary.RiskDistribution[fn.Risk]++
	}

	if summary.TotalFunctions > 0 {
		summary.AverageLOC = float64(totalLOC) / float64(summary.TotalFunctions)
	}

	// File statistics
	summary.TotalFiles = len(files)
	for _, file := range files {
		switch file.Category {
		case "large":
			summary.LargeFiles++
		case "medium":
			summary.MediumFiles++
		case "small":
			summary.SmallFiles++
		}
	}

	return summary
}

// GenerateSizeReport creates a formatted size analysis report
func GenerateSizeReport(functions []FunctionSize, files []FileSize) string {
	if len(functions) == 0 && len(files) == 0 {
		return "No code found for size analysis."
	}

	summary := ComputeSizeSummary(functions, files)

	var report strings.Builder

	// Header
	report.WriteString("📏 Code Size Analysis Report\n")
	report.WriteString("===========================\n\n")

	// Function statistics
	if len(functions) > 0 {
		report.WriteString("🔧 Function Size Statistics:\n")
		report.WriteString(fmt.Sprintf("   • Total Functions: %d\n", summary.TotalFunctions))
		report.WriteString(fmt.Sprintf("   • Average Lines of Code: %.2f\n", summary.AverageLOC))
		report.WriteString(fmt.Sprintf("   • Maximum Function Size: %d lines\n", summary.MaxLOC))
		report.WriteString(fmt.Sprintf("   • Large Functions (≥50 LOC): %d\n", summary.LargeFunctions))
		report.WriteString(fmt.Sprintf("   • Medium Functions (20-49 LOC): %d\n", summary.MediumFunctions))
		report.WriteString(fmt.Sprintf("   • Small Functions (<20 LOC): %d\n\n", summary.SmallFunctions))

		// Top large functions
		report.WriteString("🔝 Top 10 Largest Functions:\n")
		for i, fn := range functions[:min(10, len(functions))] {
			icon := getSizeIcon(fn.LOC)
			report.WriteString(fmt.Sprintf("   %d. %s %s (%s:%d) - %d lines\n",
				i+1, icon, fn.Name, fn.File, fn.Line, fn.LOC))
		}
		report.WriteString("\n")
	}

	// File statistics
	if len(files) > 0 {
		report.WriteString("📁 File Size Statistics:\n")
		report.WriteString(fmt.Sprintf("   • Total Files: %d\n", summary.TotalFiles))
		report.WriteString(fmt.Sprintf("   • Large Files (≥500 LOC): %d\n", summary.LargeFiles))
		report.WriteString(fmt.Sprintf("   • Medium Files (200-499 LOC): %d\n", summary.MediumFiles))
		report.WriteString(fmt.Sprintf("   • Small Files (<200 LOC): %d\n\n", summary.SmallFiles))

		// Top large files
		report.WriteString("📂 Top 10 Largest Files:\n")
		for i, file := range files[:min(10, len(files))] {
			icon := getSizeIcon(file.LOC)
			report.WriteString(fmt.Sprintf("   %d. %s %s - %d lines\n",
				i+1, icon, file.File, file.LOC))
		}
		report.WriteString("\n")
	}

	// Risk distribution
	report.WriteString("⚠️  Risk Distribution:\n")
	for risk, count := range summary.RiskDistribution {
		report.WriteString(fmt.Sprintf("   • %s: %d items\n", risk, count))
	}

	return report.String()
}

// getSizeIcon returns an appropriate icon based on size
func getSizeIcon(loc int) string {
	switch {
	case loc >= 100:
		return "🚨"
	case loc >= 50:
		return "⚠️"
	case loc >= 20:
		return "⚡"
	default:
		return "✅"
	}
}
