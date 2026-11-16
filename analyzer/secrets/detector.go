// Package secrets finds credentials committed to source code.
//
// Detection runs on two levels. Level one matches well-known credential
// formats (cloud keys, VCS tokens, private keys, DSNs with passwords) and is
// nearly free of false positives. Level two looks at string literals assigned
// to identifiers that name a secret and requires the value to look random.
package secrets

import (
	"go/ast"
	"go/token"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Level identifies how a finding was detected.
type Level int

const (
	// LevelPattern is a match on a known credential format.
	LevelPattern Level = 1
	// LevelContext is a random-looking literal assigned to a secret-named identifier.
	LevelContext Level = 2
)

// Finding is a detected secret. Value is redacted.
type Finding struct {
	Kind       string
	Level      Level
	Confidence float64
	Value      string
	Name       string
	Pos        token.Pos
	End        token.Pos
	Line       int
	Column     int
}

type pattern struct {
	kind   string
	re     *regexp.Regexp
	accept func(match []string) bool
}

var patterns = []pattern{
	{kind: "AWS access key", re: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`), accept: func(m []string) bool { return !strings.HasSuffix(m[1], "EXAMPLE") }},
	{kind: "GitHub token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{36,})\b`)},
	{kind: "GitHub fine-grained token", re: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{22,})\b`)},
	{kind: "GitLab token", re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20,})\b`)},
	{kind: "Slack token", re: regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b`)},
	{kind: "Stripe live key", re: regexp.MustCompile(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`)},
	{kind: "Google API key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`)},
	{kind: "private key", re: regexp.MustCompile(`(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----)`)},
	{kind: "connection string with password", re: regexp.MustCompile(`\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqps?)://([^:/\s@]+):([^@\s]+)@([^/:?\s]+))`), accept: acceptDSN},
}

var templateVar = regexp.MustCompile(`\$\{|\$\(|\{\{|%[-+# 0-9.]*[svdqxX]|^<.*>$|^\$[A-Z_]+$`)

var placeholderHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "0.0.0.0": true, "::1": true, "example.com": true, "host": true, "hostname": true, "db": true}

func acceptDSN(m []string) bool {
	password, host := m[3], strings.ToLower(m[4])
	if placeholderHosts[host] || strings.HasSuffix(host, ".example.com") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".test") {
		return false
	}
	return !isPlaceholder(password)
}

// isPlaceholder reports whether v is a template variable or an obvious stand-in.
func isPlaceholder(v string) bool {
	lower := strings.ToLower(v)
	switch {
	case v == "", templateVar.MatchString(v), strings.Trim(v, "*x.") == "":
		return true
	case strings.Contains(lower, "password") || strings.Contains(lower, "changeme") || strings.Contains(lower, "example") ||
		strings.Contains(lower, "placeholder") || strings.Contains(lower, "redacted") || strings.Contains(lower, "your") ||
		strings.Contains(lower, "xxxx") || strings.Contains(lower, "dummy") || strings.Contains(lower, "secret"):
		return true
	}
	return false
}

// ScanText applies the pattern level to arbitrary text and returns findings
// with byte offsets in Pos/End (relative to the start of text, plus one).
func ScanText(text string) []Finding {
	var out []Finding
	for _, p := range patterns {
		for _, idx := range p.re.FindAllStringSubmatchIndex(text, -1) {
			groups := make([]string, len(idx)/2)
			for i := range groups {
				if idx[2*i] >= 0 {
					groups[i] = text[idx[2*i]:idx[2*i+1]]
				}
			}
			if p.accept != nil && !p.accept(groups) {
				continue
			}
			start, end := idx[2], idx[3]
			line := 1 + strings.Count(text[:start], "\n")
			col := start - strings.LastIndex(text[:start], "\n")
			out = append(out, Finding{Kind: p.kind, Level: LevelPattern, Confidence: 0.98, Value: Redact(text[start:end]),
				Pos: token.Pos(start + 1), End: token.Pos(end + 1), Line: line, Column: col})
		}
	}
	return out
}

// ScanFile inspects the string literals and comments of a parsed Go file.
// Positions refer to fset.
func ScanFile(fset *token.FileSet, file *ast.File) []Finding {
	var out []Finding
	seen := map[token.Pos]bool{}
	add := func(f Finding) {
		if !seen[f.Pos] {
			seen[f.Pos] = true
			p := fset.Position(f.Pos)
			f.Line, f.Column = p.Line, p.Column
			out = append(out, f)
		}
	}
	hit := map[*ast.BasicLit]bool{}
	for _, group := range file.Comments {
		for _, c := range group.List {
			for _, f := range ScanText(c.Text) {
				f.Pos = c.Pos() + f.Pos - 1
				f.End = c.Pos() + f.End - 1
				add(f)
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			for _, f := range ScanText(lit.Value) {
				f.Pos = lit.Pos() + f.Pos - 1
				f.End = lit.Pos() + f.End - 1
				add(f)
				hit[lit] = true
			}
		}
		return true
	})
	if strings.HasSuffix(fset.Position(file.Pos()).Filename, "_test.go") {
		return out
	}
	context := func(name string, value ast.Expr) {
		if lit, ok := value.(*ast.BasicLit); ok && !hit[lit] {
			if f, ok := contextFinding(name, lit); ok {
				add(f)
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if i < len(x.Values) {
					context(name.Name, x.Values[i])
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					context(identName(lhs), x.Rhs[i])
				}
			}
		case *ast.KeyValueExpr:
			key := identName(x.Key)
			if lit, ok := x.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				key, _ = strconv.Unquote(lit.Value)
			}
			context(key, x.Value)
		}
		return true
	})
	return out
}

func identName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// contextFinding checks a string literal assigned to the identifier name.
func contextFinding(name string, lit *ast.BasicLit) (Finding, bool) {
	if name == "" || lit.Kind != token.STRING {
		return Finding{}, false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return Finding{}, false
	}
	kind, password := SecretName(name)
	if kind == "" || !LooksSecret(v, password) {
		return Finding{}, false
	}
	return Finding{Kind: kind, Level: LevelContext, Confidence: 0.8, Value: Redact(v), Name: name, Pos: lit.Pos(), End: lit.End()}, true
}

var (
	secretWords = map[string]string{
		"secret": "secret", "password": "password", "passwd": "password", "pwd": "password", "passphrase": "password",
		"apikey": "API key", "privatekey": "private key", "signingkey": "signing key", "authtoken": "auth token",
		"accesstoken": "access token", "refreshtoken": "refresh token", "clientsecret": "secret", "secretkey": "secret",
		"apitoken": "API token", "bearertoken": "auth token",
	}
	secretPairs = map[[2]string]string{
		{"api", "key"}: "API key", {"private", "key"}: "private key", {"signing", "key"}: "signing key",
		{"auth", "token"}: "auth token", {"access", "token"}: "access token", {"refresh", "token"}: "refresh token",
		{"api", "token"}: "API token", {"bearer", "token"}: "auth token", {"access", "key"}: "access key",
		{"hmac", "key"}: "signing key", {"encryption", "key"}: "encryption key", {"master", "key"}: "encryption key",
	}
	// Identifiers ending in these words name where a secret lives, not the secret itself.
	locatorWords = map[string]bool{
		"env": true, "header": true, "name": true, "path": true, "file": true, "url": true, "uri": true, "field": true,
		"param": true, "prefix": true, "suffix": true, "pattern": true, "regex": true, "re": true,
		"type": true, "label": true, "msg": true, "message": true, "err": true, "error": true, "id": true, "len": true,
		"length": true, "hash": true, "policy": true, "rule": true, "prompt": true, "query": true, "column": true,
		"var": true, "flag": true, "dir": true, "location": true, "ref": true, "format": true, "template": true,
	}
)

// SecretName reports whether an identifier names a secret value. It returns a
// human-readable kind and whether the identifier names a password.
func SecretName(name string) (kind string, password bool) {
	words := splitWords(name)
	if len(words) == 0 {
		return "", false
	}
	last := words[len(words)-1]
	if locatorWords[last] || words[0] == "env" {
		return "", false
	}
	if len(words) >= 2 && words[len(words)-2] == "cookie" {
		return "", false
	}
	for i, w := range words {
		if k, ok := secretWords[w]; ok {
			return k, k == "password"
		}
		if i+1 < len(words) {
			if k, ok := secretPairs[[2]string{w, words[i+1]}]; ok {
				return k, false
			}
		}
	}
	joined := strings.Join(words, "")
	for w, k := range secretWords {
		if len(w) > 6 && strings.Contains(joined, w) {
			return k, k == "password"
		}
	}
	return "", false
}

var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// LooksSecret reports whether v could be a real secret value. Passwords need
// only be a plausible single token; other secrets must be long and random.
func LooksSecret(v string, password bool) bool {
	n := utf8.RuneCountInString(v)
	if strings.IndexFunc(v, unicode.IsSpace) >= 0 || envName.MatchString(v) || isPlaceholder(v) ||
		strings.Contains(v, "://") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") {
		return false
	}
	if password {
		return n >= 8 && charClasses(v) >= 2
	}
	return n >= 12 && Entropy(v) >= 3.5
}

func charClasses(v string) int {
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	n := utf8.RuneCountInString(s)
	if n == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// Redact keeps a short prefix of a secret for identification.
func Redact(v string) string {
	runes := []rune(v)
	if len(runes) <= 8 {
		return strings.Repeat("*", len(runes))
	}
	keep := 4
	if strings.HasPrefix(v, "-----BEGIN") {
		return v
	}
	return string(runes[:keep]) + strings.Repeat("*", len(runes)-keep)
}

func splitWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, c := range runes {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			flush()
		case unicode.IsUpper(c) && len(cur) > 0 && (unicode.IsLower(cur[len(cur)-1]) || i+1 < len(runes) && unicode.IsLower(runes[i+1])):
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
	}
	flush()
	return words
}
