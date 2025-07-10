// Package metrics provides analysis of code quality metrics such as function and file size.
package metrics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// FunctionSize stores metrics about a function's line length.
type FunctionSize struct {
	Name     string // Function name
	LOC      int    // Lines of code
	File     string // File path
	Line     int    // Line number where the function starts
	Exported bool   // Whether function is exported
}

// FileSize stores metrics about a file's total lines of code.
type FileSize struct {
	File string // File path
	LOC  int    // Total lines of code
}

// AnalyzeFunctionSizes parses Go files and returns a list of function sizes.
func AnalyzeFunctionSizes(files []string) ([]FunctionSize, error) {
	var result []FunctionSize
	fset := token.NewFileSet()

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		node, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			continue
		}

		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			start := fset.Position(fn.Body.Pos())
			end := fset.Position(fn.Body.End())
			loc := end.Line - start.Line + 1

			result = append(result, FunctionSize{
				Name:     fn.Name.Name,
				LOC:      loc,
				File:     filepath.ToSlash(start.Filename),
				Line:     start.Line,
				Exported: fn.Name.IsExported(),
			})
		}
	}

	return result, nil
}

// AnalyzeFileSizes returns line counts for each provided Go source file.
func AnalyzeFileSizes(files []string) ([]FileSize, error) {
	var result []FileSize

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Count(string(content), "\n")
		if lines == 0 {
			lines = 1
		}

		result = append(result, FileSize{
			File: filepath.ToSlash(path),
			LOC:  lines,
		})
	}

	return result, nil
}
