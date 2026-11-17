package yaml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/rules"
)

func TestLoadEnabled(t *testing.T) {
	for _, tc := range []struct {
		name, setting string
		enabled       bool
	}{
		{"default", "", true}, {"disabled", "enabled: false\n", false}, {"enabled", "enabled: true\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules.Clear()
			t.Cleanup(rules.Clear)
			path := filepath.Join(t.TempDir(), "rule.yaml")
			if err := os.WriteFile(path, []byte("id: example\npattern: fmt.Println($X)\n"+tc.setting), 0600); err != nil {
				t.Fatal(err)
			}
			if err := LoadFromFile(path); err != nil {
				t.Fatal(err)
			}
			r, ok := rules.Get("example")
			if !ok || r.Enabled != tc.enabled {
				t.Fatalf("unexpected rule: %+v", r)
			}
			issues, err := r.Engine(&analyzer.AnalyzerContext{})
			if err != nil || len(issues) != 0 {
				t.Fatalf("unexpected findings: %v, %v", issues, err)
			}
		})
	}
}

func TestInvalidRule(t *testing.T) {
	for _, src := range []string{"pattern: foo()", "id: example"} {
		path := filepath.Join(t.TempDir(), "rule.yaml")
		if err := os.WriteFile(path, []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
		if err := LoadFromFile(path); err == nil {
			t.Fatalf("accepted invalid rule %q", src)
		}
	}
}
