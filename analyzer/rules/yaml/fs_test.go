package yaml

import (
	"testing"
	"testing/fstest"

	"github.com/Voskan/codexsentinel/v2/analyzer/rules"
)

func TestLoadFromFSSkipsExamplesAndDisabledRules(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/a.yaml":         {Data: []byte("id: a\npattern: fmt.Println($X)\n---\nid: off\npattern: f($X)\nenabled: false\n")},
		"rules/b.yml":          {Data: []byte("id: b\npattern: g($X)\n")},
		"rules/example-x.yaml": {Data: []byte("id: example\npattern: h($X)\n")},
		"rules/readme.txt":     {Data: []byte("not a rule")},
	}
	compiled, err := LoadFromFS(fsys, "rules")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range Registrations(compiled) {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("ids = %v, want [a b]", ids)
	}
}

func TestLoadFromFSReportsInvalidRules(t *testing.T) {
	fsys := fstest.MapFS{"rules/bad.yaml": {Data: []byte("id: bad\npattern: \"f(\"\n")}}
	if _, err := LoadFromFS(fsys, "rules"); err == nil {
		t.Fatal("invalid pattern accepted")
	}
}

func TestLoadFromFileIsIdempotent(t *testing.T) {
	rules.Clear()
	t.Cleanup(rules.Clear)
	fsys := fstest.MapFS{"r.yaml": {Data: []byte("id: twice\npattern: fmt.Println($X)\n")}}
	for i := 0; i < 2; i++ {
		compiled, err := compileFS(fsys, ".", false)
		if err != nil {
			t.Fatal(err)
		}
		if err := registerCompiled(compiled); err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
	}
	if len(rules.All()) != 1 {
		t.Fatalf("want one registered rule, got %d", len(rules.All()))
	}
}
