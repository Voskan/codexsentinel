package ignore

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryIgnoreFile(t *testing.T) {
	m := NewManager()
	if err := m.LoadFile(filepath.Join("..", "..", ".codexsentinel.ignore")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		file string
		rule string
		want bool
	}{
		{"a/b/foo.pb.go", "sql-injection", true},
		{"a/b/foo.pb.go", "anything", true},
		{"vendor/pkg/x.go", "xss", true},
		{"sub/testdata/xss.go", "sql-injection", true},
		{"pkg/service/user.go", "global-variable", false},
		{"pkg/service/user.go", "sql-injection", false},
		{"bin/codex-cli", "sql-injection", true},
	}
	for _, c := range cases {
		if got := m.IsIgnored(c.file, 10, c.rule); got != c.want {
			t.Errorf("%s %s: got %v, want %v", c.file, c.rule, got, c.want)
		}
	}
}

func TestParseLineForms(t *testing.T) {
	m := NewManager()
	m.SetRoot("/repo")
	src := `
**/*.pb.go
/vendor/
.codex_cache/
global-variable
handlers/user.go:42 sql-injection # validated
pkg/legacy/*.go sql-injection,xss # legacy admin
`
	if err := m.Load(strings.NewReader(src)); err != nil {
		t.Fatal(err)
	}
	rules := m.Rules()
	if len(rules) != 6 {
		t.Fatalf("parsed %d rules", len(rules))
	}
	if rules[0].File != "**/*.pb.go" || rules[0].RuleIDs[0] != "*" || rules[3].File != "" || rules[3].RuleIDs[0] != "global-variable" {
		t.Fatalf("single-token lines parsed incorrectly: %+v", rules[:4])
	}
	if rules[4].Line != 42 || rules[4].Comment != "validated" {
		t.Fatalf("location rule parsed incorrectly: %+v", rules[4])
	}
	checks := []struct {
		file string
		line int
		rule string
		want bool
	}{
		{"/repo/handlers/user.go", 42, "sql-injection", true},
		{"handlers/user.go", 43, "sql-injection", false},
		{"/repo/pkg/legacy/admin.go", 7, "xss", true},
		{"pkg/legacy/admin.go", 7, "sql-injection", true},
		{"pkg/legacy/admin.go", 7, "ssrf", false},
		{"/repo/.codex_cache/x.go", 1, "ssrf", true},
		{"/repo/api/gen/api.pb.go", 1, "ssrf", true},
	}
	for _, c := range checks {
		if got := m.IsIgnored(c.file, c.line, c.rule); got != c.want {
			t.Errorf("%s:%d %s: got %v, want %v", c.file, c.line, c.rule, got, c.want)
		}
	}
}
