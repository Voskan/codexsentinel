package flow

import (
	"go/ast"
	"strings"
)

// Sink represents a dangerous function that can be exploited if it receives tainted input.
type Sink struct {
	Package     string   // Package name (e.g., "os", "net/http", "database/sql")
	Function    string   // Function name (e.g., "Open", "Exec", "Get")
	MatchArgs   []int    // Indexes of arguments that must be checked for taint
	Description string   // Short description of the sink behavior
	Tags        []string // Tags: "fs", "net", "cmd", "sql", etc.
}

// SinkRegistry contains known sinks used in taint analysis.
type SinkRegistry struct {
	sinks []Sink
}

// NewSinkRegistry creates and initializes a SinkRegistry with built-in sinks.
func NewSinkRegistry() *SinkRegistry {
	return &SinkRegistry{
		sinks: []Sink{
			{Package: "os", Function: "Open", MatchArgs: []int{0}, Description: "Filesystem access", Tags: []string{"fs"}},
			{Package: "os", Function: "OpenFile", MatchArgs: []int{0}, Description: "Filesystem access", Tags: []string{"fs"}},
			{Package: "os/exec", Function: "Command", MatchArgs: []int{0, 1}, Description: "Command execution", Tags: []string{"cmd"}},
			{Package: "database/sql", Function: "Exec", MatchArgs: []int{0}, Description: "SQL execution", Tags: []string{"sql"}},
			{Package: "net/http", Function: "Get", MatchArgs: []int{0}, Description: "HTTP requests", Tags: []string{"net"}},
			{Package: "html/template", Function: "Execute", MatchArgs: []int{1}, Description: "Template execution", Tags: []string{"template"}},
			{Package: "database/sql", Function: "Query", MatchArgs: []int{0}, Description: "SQL query", Tags: []string{"sql"}},
			{Package: "fmt", Function: "Printf", MatchArgs: []int{0}, Description: "Output formatting", Tags: []string{"output"}},
			{Package: "fmt", Function: "Sprintf", MatchArgs: []int{0}, Description: "String formatting", Tags: []string{"output"}},
		},
	}
}

// Match checks if the given call expression is a known sink.
// It returns the matched Sink and the argument positions that should be checked.
func (sr *SinkRegistry) Match(call *ast.CallExpr) (*Sink, []int) {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			pkgName := ident.Name
			funcName := sel.Sel.Name

			for _, sink := range sr.sinks {
				if strings.HasSuffix(sink.Package, pkgName) && sink.Function == funcName {
					return &sink, sink.MatchArgs
				}
			}
		}
	}
	return nil, nil
}

// All returns all registered sinks.
func (sr *SinkRegistry) All() []Sink {
	return sr.sinks
}
