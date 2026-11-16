package assets_test

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/rules/yaml"
	"github.com/Voskan/codexsentinel/assets"
)

func TestBuiltinRulesCompile(t *testing.T) {
	compiled, err := yaml.LoadFromFS(assets.BuiltinRulesFS, "rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) == 0 {
		t.Fatal("no built-in rules embedded")
	}
	seen := map[string]bool{}
	for _, c := range compiled {
		if seen[c.Rule.ID] {
			t.Errorf("duplicate rule ID %s", c.Rule.ID)
		}
		seen[c.Rule.ID] = true
		if !c.Rule.IsEnabled() {
			t.Errorf("disabled rule %s loaded", c.Rule.ID)
		}
	}
	if seen["go.example.reflected-write"] {
		t.Error("example rule loaded")
	}
}
