package ast

import (
	"fmt"
	"go/ast"
	"go/token"
)

// NodeHandler defines a function that handles a specific AST node.
type NodeHandler func(node ast.Node, path []ast.Node)

// Walker allows walking through the AST with custom handlers per node type.
type Walker struct {
	fset     *token.FileSet
	handlers map[string][]NodeHandler
}

// NewWalker creates a new AST walker.
func NewWalker(fset *token.FileSet) *Walker {
	return &Walker{
		fset:     fset,
		handlers: make(map[string][]NodeHandler),
	}
}

// RegisterHandler registers a handler for the given node type (e.g. *ast.CallExpr).
func (w *Walker) RegisterHandler(nodeType string, handler NodeHandler) {
	w.handlers[nodeType] = append(w.handlers[nodeType], handler)
}

// WalkFile walks the AST of the given file.
func (w *Walker) WalkFile(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		path := buildPath(n)
		w.dispatch(n, path)
		return true
	})
}

// dispatch invokes handlers registered for the node type.
func (w *Walker) dispatch(n ast.Node, path []ast.Node) {
	if n == nil {
		return
	}
	nodeType := nodeTypeName(n)
	for _, handler := range w.handlers[nodeType] {
		handler(n, path)
	}
}

// nodeTypeName returns the type name of an AST node, e.g. "*ast.CallExpr".
func nodeTypeName(n ast.Node) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%T", n)
}

// buildPath builds a partial path (not complete ancestry, just current node for now).
func buildPath(n ast.Node) []ast.Node {
	return []ast.Node{n}
}
