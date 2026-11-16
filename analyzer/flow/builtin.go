package flow

import "github.com/Voskan/codexsentinel/analyzer/result"

// DefaultRegistry returns the built-in catalog of sources, sinks and sanitizers.
func DefaultRegistry() *Registry {
	return &Registry{
		Sources:    builtinSources(),
		Sinks:      builtinSinks(),
		Sanitizers: builtinSanitizers(),
		Categories: builtinCategories(),
	}
}

func builtinSources() []SourceSpec {
	var out []SourceSpec
	for _, m := range []string{"FormValue", "PostFormValue", "PathValue", "Cookie", "Cookies", "Referer", "UserAgent"} {
		out = append(out, SourceSpec{Package: "net/http", Receiver: "Request", Function: m, Tags: []string{"http"}})
	}
	for _, f := range []string{"URL", "Header", "Body", "Form", "PostForm", "MultipartForm", "RequestURI", "Host", "Trailer"} {
		out = append(out, SourceSpec{Package: "net/http", Receiver: "Request", Function: f, Kind: SourceField, Tags: []string{"http"}})
	}
	return out
}

func builtinSinks() []SinkSpec {
	var out []SinkSpec
	for _, recv := range []string{"DB", "Tx", "Conn"} {
		for _, m := range []string{"Query", "QueryRow", "Exec", "Prepare"} {
			out = append(out, SinkSpec{Package: "database/sql", Receiver: recv, Function: m, CheckArgs: []int{0}, WriterArg: -1, Category: "sql-injection", Description: "a SQL query"})
			out = append(out, SinkSpec{Package: "database/sql", Receiver: recv, Function: m + "Context", CheckArgs: []int{1}, WriterArg: -1, Category: "sql-injection", Description: "a SQL query"})
		}
	}
	return out
}

func builtinSanitizers() []SanitizerSpec { return nil }

func builtinCategories() map[string]CategoryInfo {
	return map[string]CategoryInfo{
		"sql-injection": {Title: "SQL Injection", CWE: "CWE-89", OWASP: "A05:2025", Severity: result.SeverityHigh,
			Suggestion: "Use parameterized queries with placeholders instead of building SQL from untrusted input."},
	}
}
