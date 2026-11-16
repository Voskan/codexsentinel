package flow

import "github.com/Voskan/codexsentinel/analyzer/result"

func sanitizer(pkg, recv, fn string, categories ...string) SanitizerSpec {
	return SanitizerSpec{Package: pkg, Receiver: recv, Function: fn, Categories: categories}
}

// builtinSanitizers lists functions whose results are safe for some or all categories.
func builtinSanitizers() []SanitizerSpec {
	var out []SanitizerSpec
	for _, fn := range []string{"Atoi", "ParseInt", "ParseUint", "ParseFloat", "ParseBool", "ParseComplex"} {
		out = append(out, sanitizer("strconv", "", fn, "*"))
	}
	out = append(out,
		sanitizer("github.com/google/uuid", "", "Parse", "*"),
		sanitizer("github.com/google/uuid", "", "MustParse", "*"),
		sanitizer("github.com/google/uuid", "", "ParseBytes", "*"),
		sanitizer("encoding/hex", "", "EncodeToString", "*"),
		sanitizer("net/netip", "", "ParseAddr", "*"),
		sanitizer("net/netip", "", "MustParseAddr", "*"),
		sanitizer("crypto/sha256", "", "Sum256", "*"),
		sanitizer("crypto/sha512", "", "Sum512", "*"),
		sanitizer("crypto/sha1", "", "Sum", "*"),
		sanitizer("crypto/md5", "", "Sum", "*"),
		sanitizer("hash", "Hash", "Sum", "*"),
		sanitizer("encoding/base64", "Encoding", "EncodeToString", "sql-injection", "command-injection", "xss"),

		sanitizer("html", "", "EscapeString", "xss"),
		sanitizer("html/template", "", "HTMLEscapeString", "xss"),
		sanitizer("html/template", "", "JSEscapeString", "xss"),
		sanitizer("html/template", "", "HTMLEscaper", "xss"),
		sanitizer("html/template", "", "JSEscaper", "xss"),
		sanitizer("html/template", "", "URLQueryEscaper", "xss"),
		sanitizer("text/template", "", "HTMLEscapeString", "xss"),
		sanitizer("encoding/json", "", "Marshal", "xss"),
		sanitizer("github.com/microcosm-cc/bluemonday", "Policy", "Sanitize", "xss"),
		sanitizer("github.com/microcosm-cc/bluemonday", "Policy", "SanitizeBytes", "xss"),
		sanitizer("net/url", "", "QueryEscape", "xss", "sql-injection", "command-injection", "path-traversal"),
		sanitizer("net/url", "", "PathEscape", "xss", "sql-injection", "command-injection", "path-traversal"),

		sanitizer("path/filepath", "", "Base", "path-traversal"),
		sanitizer("path", "", "Base", "path-traversal"),

		sanitizer("github.com/lib/pq", "", "QuoteIdentifier", "sql-injection"),
		sanitizer("github.com/lib/pq", "", "QuoteLiteral", "sql-injection"),
		sanitizer("github.com/jackc/pgx/v5", "Identifier", "Sanitize", "sql-injection"),
	)
	return out
}

func builtinCategories() map[string]CategoryInfo {
	return map[string]CategoryInfo{
		"sql-injection": {Title: "SQL Injection", CWE: "CWE-89", OWASP: "A05:2025", Severity: result.SeverityHigh,
			Suggestion: "Use parameterized queries with placeholders ($1 or ?) instead of building SQL from untrusted input.",
			References: []string{"https://cwe.mitre.org/data/definitions/89.html", "https://go.dev/doc/database/sql-injection"}},
		"command-injection": {Title: "OS Command Injection", CWE: "CWE-78", OWASP: "A05:2025", Severity: result.SeverityCritical,
			Suggestion: "Do not pass untrusted input to a shell; use a fixed executable with a validated allowlist of arguments.",
			References: []string{"https://cwe.mitre.org/data/definitions/78.html"}},
		"path-traversal": {Title: "Path Traversal", CWE: "CWE-22", OWASP: "A01:2025", Severity: result.SeverityHigh, TrustLocalSources: true,
			Suggestion: "Use os.OpenRoot(baseDir) (Go 1.24+) to confine filesystem access and prevent symlink/TOCTOU path traversal, or restrict to filepath.Base(name).",
			References: []string{"https://cwe.mitre.org/data/definitions/22.html", "https://go.dev/blog/osroot"}},
		"ssrf": {Title: "Server-Side Request Forgery", CWE: "CWE-918", OWASP: "A01:2025", Severity: result.SeverityHigh,
			Suggestion: "Validate the scheme and host of outbound URLs against an allowlist before issuing the request.",
			References: []string{"https://cwe.mitre.org/data/definitions/918.html"}},
		"xss": {Title: "Cross-Site Scripting", CWE: "CWE-79", OWASP: "A05:2025", Severity: result.SeverityHigh,
			Suggestion: "Render HTML with html/template or escape untrusted data with html.EscapeString before writing it to the response.",
			References: []string{"https://cwe.mitre.org/data/definitions/79.html"}},
		"open-redirect": {Title: "Open Redirect", CWE: "CWE-601", OWASP: "A01:2025", Severity: result.SeverityMedium,
			Suggestion: "Redirect only to relative paths or to hosts from an allowlist.",
			References: []string{"https://cwe.mitre.org/data/definitions/601.html"}},
	}
}
