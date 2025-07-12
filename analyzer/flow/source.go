package flow

import (
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Source represents a function that returns user input or untrusted data.
type Source struct {
	Package     string   // Package name (e.g., "net/http", "os")
	Function    string   // Function name (e.g., "FormValue", "Getenv")
	Description string   // Short description of the source behavior
	Tags        []string // Tags: "http", "env", "fs", etc.
}

// SourceRegistry contains known sources used in taint analysis.
type SourceRegistry struct {
	sources []Source
}

// NewSourceRegistry creates and initializes a SourceRegistry with built-in sources.
func NewSourceRegistry() *SourceRegistry {
	return &SourceRegistry{
		sources: []Source{
			{Package: "net/http", Function: "FormValue", Description: "HTTP form data", Tags: []string{"http"}},
			{Package: "net/http", Function: "Query", Description: "HTTP query parameters", Tags: []string{"http"}},
			{Package: "os", Function: "Getenv", Description: "Environment variable", Tags: []string{"env"}},
			{Package: "bufio", Function: "ReadString", Description: "User input from stdin", Tags: []string{"input"}},
			{Package: "fmt", Function: "Scanf", Description: "User input", Tags: []string{"input"}},
			{Package: "os", Function: "Getenv", Description: "Environment variable", Tags: []string{"env"}},
			{Package: "net/http", Function: "PostFormValue", Description: "HTTP POST form data", Tags: []string{"http"}},
		},
	}
}

// MatchCall checks if the given SSA call is a known source.
func (sr *SourceRegistry) MatchCall(call *ssa.Call) bool {
	if call.Call.StaticCallee() == nil {
		return false
	}

	callee := call.Call.StaticCallee()
	pkgPath := callee.Pkg.Pkg.Path()
	funcName := callee.Name()

	for _, source := range sr.sources {
		if strings.HasSuffix(pkgPath, source.Package) && source.Function == funcName {
			return true
		}
	}
	return false
}

// MatchParameter checks if the given SSA parameter is a known source.
func (sr *SourceRegistry) MatchParameter(param *ssa.Parameter) bool {
	// Check if parameter name suggests user input
	paramName := strings.ToLower(param.Name())
	suspiciousNames := []string{"input", "user", "data", "param", "arg", "value"}

	for _, name := range suspiciousNames {
		if strings.Contains(paramName, name) {
			return true
		}
	}
	return false
}

// All returns all registered sources.
func (sr *SourceRegistry) All() []Source {
	return sr.sources
}
