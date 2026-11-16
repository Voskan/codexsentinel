package deps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

const testGoMod = `module example.com/app

go 1.24.2

require (
	github.com/foo/bar v1.2.3
	github.com/old/lib v1.0.0
	github.com/local/thing v0.1.0
)

replace github.com/old/lib => github.com/new/lib v1.5.0

replace github.com/local/thing => ./thing
`

var testEntries = map[string]string{
	"GO-2024-0001": `{"id":"GO-2024-0001","summary":"Request smuggling in bar","aliases":["CVE-2024-1111"],
		"affected":[{"package":{"name":"github.com/foo/bar","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.5"}]}],
			"ecosystem_specific":{"imports":[{"path":"github.com/foo/bar/parse","symbols":["Parse","Reader.Next"]}]}}]}`,
	"GO-2024-0009": `{"id":"GO-2024-0009","summary":"Old bug","affected":[{"package":{"name":"github.com/foo/bar","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}`,
	"GO-2024-0002": `{"id":"GO-2024-0002","summary":"net/http header leak",
		"affected":[{"package":{"name":"stdlib","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"1.24.0"},{"fixed":"1.24.3"}]}],
			"ecosystem_specific":{"imports":[{"path":"net/http","symbols":["Client.Do"]}]}}]}`,
	"GHSA-aaaa-bbbb-cccc": `{"id":"GHSA-aaaa-bbbb-cccc","summary":"lib panics","database_specific":{"severity":"MODERATE"},
		"references":[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}],
		"affected":[{"package":{"name":"github.com/new/lib","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"1.4.0"},{"fixed":"1.5.1"}]}]}]}`,
}

type fakeOSV struct {
	mu      sync.Mutex
	queries []osvQuery
	fetches map[string]int
}

func (f *fakeOSV) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []osvQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode batch: %v", err)
		}
		f.mu.Lock()
		f.queries = append(f.queries, req.Queries...)
		f.mu.Unlock()
		ids := map[string][]string{
			"github.com/foo/bar@1.2.3": {"GO-2024-0001", "GO-2024-0009"},
			"github.com/new/lib@1.5.0": {"GHSA-aaaa-bbbb-cccc"},
			"stdlib@1.24.2":            {"GO-2024-0002"},
		}
		type vuln struct {
			ID string `json:"id"`
		}
		var resp struct {
			Results []struct {
				Vulns []vuln `json:"vulns"`
			} `json:"results"`
		}
		for _, q := range req.Queries {
			var res struct {
				Vulns []vuln `json:"vulns"`
			}
			for _, id := range ids[q.Package.Name+"@"+q.Version] {
				res.Vulns = append(res.Vulns, vuln{ID: id})
			}
			resp.Results = append(resp.Results, res)
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	serve := func(id string, w http.ResponseWriter) {
		f.mu.Lock()
		f.fetches[id]++
		f.mu.Unlock()
		body, ok := testEntries[id]
		if !ok {
			http.NotFound(w, nil)
			return
		}
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.PathValue("id"), "GO-") {
			t.Errorf("GO record %s fetched from OSV instead of the Go database", r.PathValue("id"))
		}
		serve(r.PathValue("id"), w)
	})
	mux.HandleFunc("GET /ID/{file}", func(w http.ResponseWriter, r *http.Request) {
		serve(strings.TrimSuffix(r.PathValue("file"), ".json"), w)
	})
	return mux
}

func writeGoMod(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOSVAuditOffline(t *testing.T) {
	fake := &fakeOSV{fetches: map[string]int{}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	client := &OSVClient{BaseURL: srv.URL, GoVulnURL: srv.URL, HTTP: srv.Client(), CacheDir: t.TempDir()}

	goMod := writeGoMod(t, testGoMod)
	reports, err := ScanDependencies(context.Background(), goMod, ScanOptions{CheckVulnerabilities: true, OSV: client, GHSA: &GHSAClient{}})
	if err != nil {
		t.Fatal(err)
	}

	queried := map[string]bool{}
	for _, q := range fake.queries {
		if q.Package.Ecosystem != "Go" {
			t.Errorf("ecosystem %q", q.Package.Ecosystem)
		}
		queried[q.Package.Name+"@"+q.Version] = true
	}
	for _, want := range []string{"github.com/foo/bar@1.2.3", "github.com/new/lib@1.5.0", "stdlib@1.24.2"} {
		if !queried[want] {
			t.Errorf("missing query %s in %v", want, queried)
		}
	}
	if queried["github.com/old/lib@1.0.0"] || len(queried) != 3 {
		t.Errorf("replaced or local modules queried: %v", queried)
	}

	got := map[string]Vulnerability{}
	for _, r := range reports {
		for _, v := range r.Vulnerabilities {
			got[r.Module+" "+v.ID] = v
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 vulnerabilities, got %v", got)
	}
	bar := got["github.com/foo/bar GO-2024-0001"]
	if bar.FixedVersion != "v1.2.5" || bar.Severity != "HIGH" || len(bar.Packages) != 1 || bar.Packages[0].Symbols[1] != "Reader.Next" {
		t.Errorf("unexpected bar vulnerability: %+v", bar)
	}
	lib := got["github.com/old/lib GHSA-aaaa-bbbb-cccc"]
	if lib.Severity != "MEDIUM" || lib.FixedVersion != "v1.5.1" || lib.Version != "v1.5.0" || lib.Reference == "" {
		t.Errorf("replace target not used: %+v", lib)
	}
	std := got["stdlib GO-2024-0002"]
	if std.FixedVersion != "1.24.3" {
		t.Errorf("unexpected stdlib vulnerability: %+v", std)
	}

	issues := ReportIssues(reports, "go.mod")
	stdIssue := false
	for _, issue := range issues {
		if issue.ID != "dependency-vulnerability" {
			t.Errorf("unexpected issue %+v", issue)
		}
		if strings.Contains(issue.Description, "Go standard library") && strings.Contains(issue.Suggestion, "toolchain to 1.24.3") {
			stdIssue = true
		}
	}
	if !stdIssue || len(issues) != 3 {
		t.Errorf("stdlib vulnerability not reported: %+v", issues)
	}

	before := fake.fetches["GO-2024-0001"]
	if _, err := client.Audit(context.Background(), []ModuleVersion{{Path: "github.com/foo/bar", Version: "v1.2.3", Required: "github.com/foo/bar"}}); err != nil {
		t.Fatal(err)
	}
	if fake.fetches["GO-2024-0001"] != before {
		t.Error("cached record fetched again")
	}
}

func TestReadGoModToolchain(t *testing.T) {
	mods, err := ReadGoMod(writeGoMod(t, "module m\n\ngo 1.23\n\ntoolchain go1.24.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].Path != StdlibModule || mods[0].Version != "1.24.5" {
		t.Fatalf("unexpected modules: %+v", mods)
	}
	mods, _ = ReadGoMod(writeGoMod(t, "module m\n\ngo 1.24\n"))
	if mods[0].Version != "1.24.0" {
		t.Fatalf("go directive without patch: %+v", mods)
	}
}

func TestGHSAQueryUsesVariables(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing token")
		}
		var body struct {
			Query     string            `json:"query"`
			Variables map[string]string `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Variables["pkg"] != `github.com/x/"y` || strings.Contains(body.Query, "github.com") {
			t.Errorf("module not passed as a variable: %+v", body)
		}
		_, _ = w.Write([]byte(`{"data":{"securityVulnerabilities":{"nodes":[
			{"package":{"name":"github.com/x/\"y"},"advisory":{"ghsaId":"GHSA-1","summary":"bad","severity":"CRITICAL","permalink":"https://github.com/advisories/GHSA-1","identifiers":[{"type":"CVE","value":"CVE-2025-1"}]},"vulnerableVersionRange":">= 1.0.0, < 1.2.5","firstPatchedVersion":{"identifier":"1.2.5"}},
			{"package":{"name":"github.com/x/\"y"},"advisory":{"ghsaId":"GHSA-2","summary":"old","severity":"LOW"},"vulnerableVersionRange":"< 0.4.0"}]}}}`))
	}))
	defer srv.Close()
	client := &GHSAClient{URL: srv.URL, Token: "test-token", HTTP: srv.Client()}
	vulns, err := client.Audit(context.Background(), []ModuleVersion{{Path: `github.com/x/"y`, Version: "v1.2.0", Required: `github.com/x/"y`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-1" || vulns[0].Version != "v1.2.0" || vulns[0].FixedVersion != "v1.2.5" || vulns[0].Severity != "CRITICAL" || vulns[0].Aliases[0] != "CVE-2025-1" {
		t.Fatalf("unexpected advisories: %+v", vulns)
	}
	if v, err := (&GHSAClient{}).Audit(context.Background(), []ModuleVersion{{Path: "a", Version: "v1.0.0"}}); err != nil || v != nil {
		t.Fatalf("query without token: %v %v", v, err)
	}
}

func TestMatchGHSARange(t *testing.T) {
	cases := []struct {
		rng, version string
		want         bool
	}{
		{">= 1.2.0, < 1.2.5", "v1.2.0", true},
		{">= 1.2.0, < 1.2.5", "1.2.4", true},
		{">= 1.2.0, < 1.2.5", "v1.2.5", false},
		{">= 1.2.0, < 1.2.5", "v1.1.9", false},
		{"< 0.4.0", "v0.3.9", true},
		{"< 0.4.0", "v0.4.0", false},
		{"= 2.1.0", "v2.1.0", true},
		{"= 2.1.0", "v2.1.1", false},
		{"<= 1.0.0", "v1.0.0-rc.1", true},
		{"> 1.0.0", "v1.0.1+incompatible", true},
	}
	for _, tc := range cases {
		got, err := MatchGHSARange(tc.rng, tc.version)
		if err != nil || got != tc.want {
			t.Errorf("MatchGHSARange(%q, %q) = %v, %v; want %v", tc.rng, tc.version, got, err, tc.want)
		}
	}
	if _, err := MatchGHSARange(">= banana", "v1.0.0"); err == nil {
		t.Error("invalid range accepted")
	}
}

func reachabilityFor(t *testing.T, mainBody string) Vulnerability {
	t.Helper()
	fx := testutil.LoadFixture(t, map[string]string{
		"vulnmod/vulnmod.go": `package vulnmod

func VulnFunc(s string) string { return s + "!" }

func SafeFunc(s string) string { return s }
`,
		"cmd/app/main.go": `package main

import (
	"fmt"

	"example.com/fixture/vulnmod"
)

func main() {
	` + mainBody + `
}
`,
	}, nil)
	bundle, err := codessa.BuildFromWorkspace(fx.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	vulns := []Vulnerability{{ID: "GO-2025-0001", Severity: "HIGH", Packages: []AffectedPackage{{Path: "example.com/fixture/vulnmod", Symbols: []string{"VulnFunc"}}}}}
	ApplyReachability(bundle, vulns)
	return vulns[0]
}

func TestReachabilityUnreachable(t *testing.T) {
	t.Parallel()
	v := reachabilityFor(t, `fmt.Println(vulnmod.SafeFunc("x"))`)
	if v.Reachable == nil || *v.Reachable || v.Severity != "LOW" {
		t.Fatalf("want unreachable LOW, got %+v", v)
	}
	issue := vulnerabilityIssue(DependencyReport{Module: "example.com/fixture", Version: "v0.0.0"}, v, result.Location{})
	if issue.Severity != result.SeverityLow || !strings.Contains(issue.Description, "(Unreachable in call graph)") || *issue.Reachable {
		t.Fatalf("unexpected issue: %+v", issue)
	}
}

func TestReachabilityReachable(t *testing.T) {
	t.Parallel()
	v := reachabilityFor(t, `fmt.Println(vulnmod.VulnFunc("x"))`)
	if v.Reachable == nil || !*v.Reachable || v.Severity != "HIGH" || !strings.HasSuffix(v.CalledBy, "main") {
		t.Fatalf("want reachable HIGH from main, got %+v", v)
	}
	issue := vulnerabilityIssue(DependencyReport{Module: "example.com/fixture", Version: "v0.0.0"}, v, result.Location{})
	if issue.Severity != result.SeverityHigh || !strings.Contains(issue.Description, "VulnFunc is called from") {
		t.Fatalf("unexpected issue: %+v", issue)
	}
}
