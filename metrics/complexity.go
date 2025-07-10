// Package metrics provides static code quality metrics such as cyclomatic complexity.
package metrics

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
)

// ComplexityResult represents the cyclomatic complexity of a single function.
type ComplexityResult struct {
	Name     string // Function name
	File     string // File path
	Line     int    // Line number
	Complexity int  // Computed cyclomatic complexity
	Exported bool   // Whether function is exported
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

			results = append(results, ComplexityResult{
				Name:      fn.Name.Name,
				File:      filepath.ToSlash(start.Filename),
				Line:      start.Line,
				Complexity: score,
				Exported:  fn.Name.IsExported(),
			})

			return false
		})
	}

	return results, nil
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
