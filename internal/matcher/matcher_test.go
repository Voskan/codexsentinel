package matcher

import "testing"

func TestGlobPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"sql-injection", "sql-injection", true},
		{"sql-*", "sql-injection", true},
		{"*-injection", "command-injection", true},
		{"sql-*", "xss", false},
		{"**/*.pb.go", "a/b/foo.pb.go", true},
		{"**/*.pb.go", "foo.pb.go", true},
		{"**/*.pb.go", "a/b/foo.go", false},
		{"/vendor/", "vendor/pkg/x.go", true},
		{"/vendor/", "internal/vendor/x.go", false},
		{"vendor/", "internal/vendor/x.go", true},
		{"**/testdata/", "sub/testdata/xss.go", true},
		{"**/testdata/*", "sub/testdata/xss.go", true},
		{"**/testdata/*", "testdata/a.go", true},
		{"pkg/**/gen.go", "pkg/gen.go", true},
		{"pkg/**/gen.go", "pkg/a/b/gen.go", true},
		{"pkg/**/gen.go", "other/pkg/a/gen.go", false},
		{"pkg/legacy/*.go", "pkg/legacy/admin.go", true},
		{"pkg/legacy/*.go", "pkg/legacy/sub/admin.go", false},
		{"pkg/legacy/*.go", "x/pkg/legacy/admin.go", false},
		{"docs/**", "docs/a/b.md", true},
		{"*.swp", "a/b/.main.go.swp", true},
		{"file?.go", "file1.go", true},
		{"file?.go", "file12.go", false},
		{"cmd/main.go", "./cmd/main.go", true},
		{"a.b", "axb", false},
	}
	for _, c := range cases {
		if got := New([]string{c.pattern}).Match(c.value); got != c.want {
			t.Errorf("%q vs %q: got %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestNegationTakesPrecedence(t *testing.T) {
	m := New([]string{"*", "!deprecated-*"})
	if !m.Match("sql-injection") || m.Match("deprecated-rule") {
		t.Fatal("negated pattern not applied")
	}
	if New(nil).Match("anything") {
		t.Fatal("empty matcher matched")
	}
	if got := m.MatchAll([]string{"a", "deprecated-b"}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("MatchAll = %v", got)
	}
}
