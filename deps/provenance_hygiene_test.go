package deps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

func writeModule(t *testing.T, goMod, goSum string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if goSum != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "go.mod")
}

func findingsOf(findings []ModuleFinding, rule string) map[string]ModuleFinding {
	out := map[string]ModuleFinding{}
	for _, f := range findings {
		if f.RuleID == rule {
			out[f.Module] = f
		}
	}
	return out
}

func TestTyposquatting(t *testing.T) {
	goMod := `module github.com/mycorp/service-a

go 1.24

require (
	github.com/gin-gonlc/gin v1.10.0
	github.com/gin-gonic/gin v1.10.0
	github.com/spf13/corba v1.8.0
	golang.org/x/crypto v0.31.0
	golang.org/x/sync v0.10.0
	golang.org/x/test v0.1.0
	github.com/mycorp/service-b v0.3.0
	github.com/go-chl/chi/v5 v5.1.0
	go.opentelemetry.io/otel/trace v1.30.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.30.0
	github.com/redis/goredis/v9 v9.0.0
	github.com/acme/widgets v1.0.0
)
`
	findings, err := AnalyzeGoModHygiene(writeModule(t, goMod, ""), HygieneOptions{Typosquatting: true})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsOf(findings, RuleTyposquatting)
	want := map[string]struct {
		line    int
		similar string
	}{
		"github.com/gin-gonlc/gin":    {6, "github.com/gin-gonic/gin"},
		"github.com/spf13/corba":      {8, "github.com/spf13/cobra"},
		"github.com/go-chl/chi/v5":    {13, "github.com/go-chi/chi"},
		"github.com/redis/goredis/v9": {16, "github.com/redis/go-redis/v9"},
	}
	for mod, w := range want {
		f, ok := got[mod]
		if !ok {
			t.Errorf("%s not reported", mod)
			continue
		}
		if f.Line != w.line || !strings.HasPrefix(f.Similar, w.similar) || f.Severity != result.SeverityHigh {
			t.Errorf("%s: line %d similar %s severity %s, want line %d similar %s", mod, f.Line, f.Similar, f.Severity, w.line, w.similar)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected typosquatting findings: %+v", got)
	}

	issues := FindingIssues(findings, "go.mod")
	for _, is := range issues {
		if is.Category != "supply-chain" || is.Location.Line < 6 || !strings.Contains(is.Description, "popular module") {
			t.Errorf("issue %+v", is)
		}
	}
}

func TestTyposquattingAllowedPrefixes(t *testing.T) {
	goMod := "module example.com/app\n\ngo 1.24\n\nrequire github.com/spf13/corba v1.8.0\n"
	findings, err := AnalyzeGoModHygiene(writeModule(t, goMod, ""), HygieneOptions{Typosquatting: true, AllowedPrefixes: []string{"github.com/spf13/"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("allowed prefix still reported: %+v", findings)
	}
}

func TestGoModHygiene(t *testing.T) {
	goMod := `module example.com/app

go 1.24

require (
	github.com/google/uuid v1.6.0
	github.com/pkg/errors v0.9.1
	example.com/shared v0.0.0
	github.com/fatih/color v1.17.0 // indirect
	github.com/stretchr/testify v1.9.0
)

replace example.com/shared => ../shared

replace github.com/stretchr/testify => github.com/stretchr/testify v1.9.1
`
	goSum := `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/stretchr/testify v1.9.1 h1:abc=
`
	path := writeModule(t, goMod, goSum)
	findings, err := AnalyzeGoModHygiene(path, HygieneOptions{Hygiene: true})
	if err != nil {
		t.Fatal(err)
	}
	local := findingsOf(findings, RuleLocalReplace)
	if f, ok := local["example.com/shared"]; !ok || f.Line != 13 || f.Severity != result.SeverityMedium {
		t.Errorf("local replace: %+v", local)
	}
	if len(local) != 1 {
		t.Errorf("remote replace reported as local: %+v", local)
	}
	sums := findingsOf(findings, RuleMissingChecksum)
	if f, ok := sums["github.com/pkg/errors"]; !ok || f.Line != 7 {
		t.Errorf("missing checksum not reported for pkg/errors: %+v", sums)
	}
	if len(sums) != 1 {
		t.Errorf("unexpected checksum findings (indirect, local and replaced modules must be skipped): %+v", sums)
	}

	if err := os.Remove(filepath.Join(filepath.Dir(path), "go.sum")); err != nil {
		t.Fatal(err)
	}
	findings, err = AnalyzeGoModHygiene(path, HygieneOptions{Hygiene: true})
	if err != nil {
		t.Fatal(err)
	}
	if sums := findingsOf(findings, RuleMissingChecksum); len(sums) != 3 || !strings.Contains(sums["github.com/google/uuid"].Message, "no go.sum") {
		t.Errorf("without go.sum: %+v", sums)
	}

	stdOnly := writeModule(t, "module example.com/tool\n\ngo 1.24\n", "")
	if findings, err := AnalyzeGoModHygiene(stdOnly, HygieneOptions{Hygiene: true, Typosquatting: true}); err != nil || len(findings) != 0 {
		t.Errorf("module without requirements: %+v, %v", findings, err)
	}
}

func TestModulePolicy(t *testing.T) {
	goMod := `module example.com/app

go 1.24

require (
	github.com/google/uuid v1.6.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	example.com/internal/lib v1.0.0
)
`
	path := writeModule(t, goMod, "")
	findings, err := AnalyzeGoModHygiene(path, HygieneOptions{DeniedPrefixes: []string{"github.com/dgrijalva"}})
	if err != nil {
		t.Fatal(err)
	}
	denied := findingsOf(findings, RulePolicyDenied)
	if f, ok := denied["github.com/dgrijalva/jwt-go"]; len(denied) != 1 || !ok || f.Line != 7 || !strings.Contains(f.Message, "denied_prefixes") {
		t.Errorf("denied prefixes: %+v", denied)
	}

	findings, err = AnalyzeGoModHygiene(path, HygieneOptions{AllowedPrefixes: []string{"example.com/", "github.com/google"}})
	if err != nil {
		t.Fatal(err)
	}
	denied = findingsOf(findings, RulePolicyDenied)
	if _, ok := denied["github.com/dgrijalva/jwt-go"]; len(denied) != 1 || !ok {
		t.Errorf("allowed prefixes: %+v", denied)
	}
	if matchesPrefix("github.com/googleapis/gax-go", []string{"github.com/google"}) {
		t.Error("prefix matched across a path element boundary")
	}
}

// fakeProxy serves module proxy answers for three modules.
func fakeProxy(t *testing.T, now time.Time) *httptest.Server {
	t.Helper()
	young := now.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	old := now.Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	routes := map[string]string{
		"/github.com/acme/fresh/@v/v1.0.0.info": `{"Version":"v1.0.0","Time":"` + young + `"}`,
		"/github.com/acme/fresh/@latest":        `{"Version":"v1.0.0"}`,
		"/github.com/acme/fresh/@v/v1.0.0.mod":  "module github.com/acme/fresh\n",

		"/github.com/acme/broken/@v/v1.0.3.info": `{"Version":"v1.0.3","Time":"` + old + `"}`,
		"/github.com/acme/broken/@latest":        `{"Version":"v1.0.6"}`,
		"/github.com/acme/broken/@v/v1.0.6.mod":  "module github.com/acme/broken\n\nretract [v1.0.0, v1.0.5] // critical security bug\n",

		"/github.com/!burnt!sushi/legacy/@v/v3.2.0+incompatible.info": `{"Version":"v3.2.0+incompatible","Time":"` + old + `"}`,
		"/github.com/!burnt!sushi/legacy/@latest":                     `{"Version":"v3.2.0+incompatible"}`,
		"/github.com/!burnt!sushi/legacy/@v/v3.2.0+incompatible.mod":  "// Deprecated: use github.com/golang-jwt/jwt/v5 instead\nmodule github.com/BurntSushi/legacy\n",
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

func TestProvenanceProxy(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	srv := fakeProxy(t, now)
	defer srv.Close()
	goMod := `module example.com/app

go 1.24

require (
	github.com/acme/fresh v1.0.0
	github.com/acme/broken v1.0.3
	github.com/BurntSushi/legacy v3.2.0+incompatible
	github.com/acme/unknown v0.1.0
	example.com/private v1.0.0
)
`
	proxy := &ProxyClient{BaseURL: srv.URL, HTTP: srv.Client(), CacheDir: t.TempDir(), Private: "example.com/private"}
	opts := ProvenanceOptions{MinModuleAgeDays: 7, Proxy: proxy, Now: func() time.Time { return now }}
	path := writeModule(t, goMod, "")
	findings, err := CheckProvenance(context.Background(), path, opts)
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findingsOf(findings, RuleYoungModule)["github.com/acme/fresh"]; !ok || f.Line != 6 || !strings.Contains(f.Message, "2 hours") {
		t.Errorf("young module: %+v", findings)
	}
	if f, ok := findingsOf(findings, RuleRetracted)["github.com/acme/broken"]; !ok || f.Severity != result.SeverityHigh || !strings.Contains(f.Message, "critical security bug") {
		t.Errorf("retracted: %+v", findings)
	}
	if f, ok := findingsOf(findings, RuleDeprecated)["github.com/BurntSushi/legacy"]; !ok || !strings.Contains(f.Message, "use github.com/golang-jwt/jwt/v5 instead") {
		t.Errorf("deprecated: %+v", findings)
	}
	if len(findings) != 3 {
		t.Errorf("unexpected findings: %+v", findings)
	}

	// The second run is answered from the cache; only the module the proxy
	// did not know is looked up again and fails.
	srv.Close()
	again, err := CheckProvenance(context.Background(), path, opts)
	if len(again) != 3 {
		t.Errorf("cached run: %+v", again)
	}
	if err == nil || strings.Contains(err.Error(), "acme/fresh") || strings.Contains(err.Error(), "acme/broken") || strings.Contains(err.Error(), "legacy") {
		t.Errorf("cached run error: %v", err)
	}

	opts.MinModuleAgeDays = 0
	opts.Proxy = &ProxyClient{BaseURL: proxy.BaseURL, HTTP: proxy.HTTP, CacheDir: proxy.CacheDir}
	if found, _ := CheckProvenance(context.Background(), path, opts); len(findingsOf(found, RuleYoungModule)) != 0 {
		t.Error("age check ran with min_module_age_days 0")
	}
}

func TestProxyFromEnv(t *testing.T) {
	cases := map[string]string{
		"":                                     DefaultProxyURL,
		"https://goproxy.io,direct":            "https://goproxy.io",
		"https://a.example/|https://b.example": "https://a.example",
		"direct":                               "",
		"off":                                  "",
	}
	for in, want := range cases {
		if got := proxyFromEnv(in); got != want {
			t.Errorf("proxyFromEnv(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanDependenciesModuleFindings(t *testing.T) {
	goMod := "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\n\nreplace example.com/shared => ./shared\n"
	path := writeModule(t, goMod, "")
	reports, err := ScanDependencies(context.Background(), path, ScanOptions{CheckHygiene: true, CheckProvenance: true})
	if err != nil {
		t.Fatal(err)
	}
	issues := ReportIssues(reports, "go.mod")
	if len(issues) != 1 || issues[0].ID != RuleLocalReplace || issues[0].Location.Line != 7 {
		t.Errorf("issues: %+v", issues)
	}
}
