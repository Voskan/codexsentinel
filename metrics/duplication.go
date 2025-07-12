// Package metrics provides analysis of code duplication between functions.
package metrics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
)

// DuplicateBlock represents two or more identical function bodies across files.
type DuplicateBlock struct {
	Hash  string  // Hash of normalized function body
	Funcs []DupFn // All functions that share this body
}

// DupFn describes a single function instance within a duplicate block.
type DupFn struct {
	Name string // Function name
	File string // File path
	Line int    // Line number
}

// AnalyzeDuplicatedFunctions scans a list of Go files and reports duplicated function bodies.
func AnalyzeDuplicatedFunctions(files []string) ([]DuplicateBlock, error) {
	type hashKey string
	hashToFuncs := make(map[hashKey][]DupFn)

	fset := token.NewFileSet()

	for _, file := range files {
		node, err := parseFile(fset, file)
		if err != nil {
			continue
		}

		ast.Inspect(node, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}

			hash, err := hashFuncBody(fset, fn.Body)
			if err != nil {
				return true
			}

			pos := fset.Position(fn.Pos())
			entry := DupFn{
				Name: fn.Name.Name,
				File: filepath.ToSlash(pos.Filename),
				Line: pos.Line,
			}

			hashToFuncs[hashKey(hash)] = append(hashToFuncs[hashKey(hash)], entry)
			return false
		})
	}

	var duplicates []DuplicateBlock
	for h, funcs := range hashToFuncs {
		if len(funcs) > 1 {
			duplicates = append(duplicates, DuplicateBlock{
				Hash:  string(h),
				Funcs: funcs,
			})
		}
	}

	return duplicates, nil
}

// parseFile parses a Go file from disk.
func parseFile(fset *token.FileSet, path string) (*ast.File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %s: %w", path, err)
	}

	node, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("cannot parse file %s: %w", path, err)
	}
	return node, nil
}

// hashFuncBody returns a normalized hash of a function body using SHA-256.
func hashFuncBody(fset *token.FileSet, body *ast.BlockStmt) (string, error) {
	var buf bytes.Buffer
	err := printer.Fprint(&buf, fset, body)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:]), nil
}
