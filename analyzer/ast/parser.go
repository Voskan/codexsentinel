package ast

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

// ParsedFile represents a parsed Go source file with its AST and FileSet.
type ParsedFile struct {
	File   *ast.File      // Parsed AST
	Fset   *token.FileSet // FileSet for position mapping
	Path   string         // Absolute file path
	Source []byte         // Raw source code (optional)
}

// ParseFile parses a Go source file into an AST with a new FileSet.
func ParseFile(path string) (*ParsedFile, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", path, err)
	}
	return ParseSource(path, src)
}

// ParseSource parses the provided Go source code (in-memory) with a new FileSet.
func ParseSource(path string, src []byte) (*ParsedFile, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Go source in %q: %w", path, err)
	}
	return &ParsedFile{
		File:   file,
		Fset:   fset,
		Path:   path,
		Source: src,
	}, nil
}
