// Package metrics provides analysis of code duplication between functions.
package metrics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/printer"
	"go/token"
	"sort"
)

// DuplicateBlock represents two or more identical function bodies.
type DuplicateBlock struct {
	Hash  string  // Hash of the normalized function body
	LOC   int     // Lines spanned by each copy of the body
	Funcs []DupFn // All functions that share this body, ordered by location
}

// DupFn describes a single function instance within a duplicate block.
type DupFn struct {
	Name string // Function name
	File string // File path
	Line int    // Line number
}

// AnalyzeDuplicates reports function bodies that occur more than once in files.
// Bodies shorter than minLOC lines (getters, trivial constructors) are ignored.
func AnalyzeDuplicates(fset *token.FileSet, files []*ast.File, minLOC int) []DuplicateBlock {
	groups := map[string]*DuplicateBlock{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			loc := bodyLines(fset, fn.Body)
			if loc < minLOC {
				continue
			}
			hash, err := hashFuncBody(fset, fn.Body)
			if err != nil {
				continue
			}
			pos := fset.Position(fn.Pos())
			block := groups[hash]
			if block == nil {
				block = &DuplicateBlock{Hash: hash, LOC: loc}
				groups[hash] = block
			}
			block.Funcs = append(block.Funcs, DupFn{Name: funcName(fn), File: pos.Filename, Line: pos.Line})
		}
	}
	var duplicates []DuplicateBlock
	for _, block := range groups {
		if len(block.Funcs) < 2 {
			continue
		}
		sort.Slice(block.Funcs, func(i, j int) bool {
			if block.Funcs[i].File != block.Funcs[j].File {
				return block.Funcs[i].File < block.Funcs[j].File
			}
			return block.Funcs[i].Line < block.Funcs[j].Line
		})
		duplicates = append(duplicates, *block)
	}
	sort.Slice(duplicates, func(i, j int) bool {
		a, b := duplicates[i].Funcs[0], duplicates[j].Funcs[0]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return duplicates
}

// hashFuncBody returns a hash of the printed function body. Comments and
// formatting differences are not part of the printed form.
func hashFuncBody(fset *token.FileSet, body *ast.BlockStmt) (string, error) {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, body); err != nil {
		return "", err
	}
	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:]), nil
}
