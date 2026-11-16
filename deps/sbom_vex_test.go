package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sbomGoMod = `module github.com/acme/shop

go 1.24.2

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/BurntSushi/toml v1.4.0+incompatible // indirect
	example.com/local v0.0.0
)

replace example.com/local => ../local
`

// The h1: hash below decodes to 32 bytes.
const ginSum = "h1:nTuyha1TYqgedzytsKYqna+DfLos46nTv2ygFy86HFU="

func writeSBOMModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	goSum := "github.com/gin-gonic/gin v1.10.0 " + ginSum + "\n" +
		"github.com/gin-gonic/gin v1.10.0/go.mod h1:4PMNQiOhvDRa013RKVbsiNwoyezlm2rm0uX/T7kzp5Y=\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(sbomGoMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "go.mod")
}

func testSBOM(t *testing.T) *SBOM {
	t.Helper()
	sb, err := ReadSBOM(writeSBOMModule(t))
	if err != nil {
		t.Fatal(err)
	}
	sb.Timestamp = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	sb.ToolVersion = "v2.0.0"
	sb.SetLicenses([]LicenseFinding{{Module: "github.com/gin-gonic/gin", License: "MIT"}, {Module: "github.com/BurntSushi/toml", License: "UNKNOWN"}})
	sb.SetCapabilities(&CapabilityReport{Modules: []ModuleCapabilities{{
		Module: "github.com/gin-gonic/gin", Capabilities: []Capability{CapNetwork, CapFSRead},
		Evidence: map[Capability]string{CapNetwork: "(*gin.Engine).Run -> net/http.ListenAndServe"},
	}}})
	return sb
}

func TestCycloneDX(t *testing.T) {
	sb := testSBOM(t)
	data, err := json.Marshal(sb.CycloneDX())
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []struct{ Name, Version string } `json:"components"`
			} `json:"tools"`
			Component struct {
				Type, Name string
				BOMRef     string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name, Version, Type, PURL string
			Hashes                    []struct{ Alg, Content string }
			Licenses                  []struct {
				License struct{ ID string } `json:"license"`
			}
			Properties []struct{ Name, Value string }
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Vulnerabilities []any `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Fatalf("header: %+v", bom)
	}
	if bom.Metadata.Timestamp != "2026-11-16T12:00:00Z" || bom.Metadata.Tools.Components[0].Name != "codexsentinel" || bom.Metadata.Component.Name != "github.com/acme/shop" {
		t.Errorf("metadata: %+v", bom.Metadata)
	}
	byName := map[string]int{}
	for i, c := range bom.Components {
		byName[c.Name] = i
	}
	if _, ok := byName["example.com/local"]; ok {
		t.Error("module replaced by a directory is listed")
	}
	gin := bom.Components[byName["github.com/gin-gonic/gin"]]
	if gin.PURL != "pkg:golang/github.com/gin-gonic/gin@v1.10.0" || gin.Type != "library" {
		t.Errorf("gin: %+v", gin)
	}
	if len(gin.Hashes) != 1 || gin.Hashes[0].Alg != "SHA-256" || gin.Hashes[0].Content != "9d3bb285ad5362a81e773cadb0a62a9daf837cba2ce3a9d3bf6ca0172f3a1c55" {
		t.Errorf("gin hashes: %+v", gin.Hashes)
	}
	if len(gin.Licenses) != 1 || gin.Licenses[0].License.ID != "MIT" {
		t.Errorf("gin licenses: %+v", gin.Licenses)
	}
	props := map[string]string{}
	caps := 0
	for _, p := range gin.Properties {
		props[p.Name] = p.Value
		if p.Name == "codexsentinel:capability" {
			caps++
		}
	}
	if caps != 2 || !strings.Contains(props["codexsentinel:capability:evidence:CAP_NETWORK"], "ListenAndServe") || props["go:sum"] != ginSum {
		t.Errorf("gin properties: %+v", gin.Properties)
	}
	toml := bom.Components[byName["github.com/BurntSushi/toml"]]
	if toml.PURL != "pkg:golang/github.com/BurntSushi/toml@v1.4.0%2Bincompatible" || len(toml.Licenses) != 0 || len(toml.Hashes) != 0 {
		t.Errorf("toml: %+v", toml)
	}
	std := bom.Components[byName["stdlib"]]
	if std.PURL != "pkg:golang/stdlib@v1.24.2" {
		t.Errorf("stdlib: %+v", std)
	}
	if bom.Dependencies[0].Ref != "pkg:golang/github.com/acme/shop" || len(bom.Dependencies[0].DependsOn) != 3 {
		t.Errorf("dependencies: %+v", bom.Dependencies)
	}
	if bom.Vulnerabilities != nil {
		t.Error("vulnerabilities listed without a lookup")
	}
	again, _ := json.Marshal(sb.CycloneDX())
	if string(again) != string(data) {
		t.Error("output is not deterministic")
	}
}

func TestPURL(t *testing.T) {
	cases := map[[2]string]string{
		{"github.com/gin-gonic/gin", "v1.10.0"}:            "pkg:golang/github.com/gin-gonic/gin@v1.10.0",
		{"gopkg.in/yaml.v3", "v3.0.1"}:                     "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
		{"github.com/a/b", "v0.0.0-20240101000000-abcdef"}: "pkg:golang/github.com/a/b@v0.0.0-20240101000000-abcdef",
		{"example.com/a@b", "v1.0.0"}:                      "pkg:golang/example.com/a%40b@v1.0.0",
		{StdlibModule, "1.24.2"}:                           "pkg:golang/stdlib@v1.24.2",
	}
	for in, want := range cases {
		if got := PURL(in[0], in[1]); got != want {
			t.Errorf("PURL(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
	if _, ok := SHA256FromGoSum("h1:short"); ok {
		t.Error("invalid hash accepted")
	}
}

func TestSPDX(t *testing.T) {
	doc := testSBOM(t).SPDX()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["spdxVersion"] != "SPDX-2.3" || out["dataLicense"] != "CC0-1.0" || out["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Fatalf("header: %v", out)
	}
	var gin *SPDXPackage
	for i := range doc.Packages {
		if doc.Packages[i].Name == "github.com/gin-gonic/gin" {
			gin = &doc.Packages[i]
		}
		for _, r := range doc.Packages[i].SPDXID {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
				t.Errorf("invalid SPDXID %q", doc.Packages[i].SPDXID)
			}
		}
	}
	if gin == nil || gin.LicenseDeclared != "MIT" || gin.ExternalRefs[0].ReferenceType != "purl" || gin.ExternalRefs[0].ReferenceLocator != "pkg:golang/github.com/gin-gonic/gin@v1.10.0" || gin.Checksums[0].Algorithm != "SHA256" {
		t.Errorf("gin package: %+v", gin)
	}
	if len(doc.Relationships) != len(doc.Packages) || doc.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Errorf("relationships: %+v", doc.Relationships)
	}
}

func TestOpenVEX(t *testing.T) {
	sb := testSBOM(t)
	no, yes := false, true
	sb.Vulns = []Vulnerability{
		{Module: "github.com/gin-gonic/gin", Version: "v1.10.0", ID: "GO-2026-0001", Aliases: []string{"CVE-2026-1111", "GHSA-aaaa-bbbb-cccc"}, Summary: "Header injection", Reachable: &no},
		{Module: "stdlib", Version: "1.24.2", ID: "GO-2026-0002", Aliases: []string{"CVE-2026-2222"}, Summary: "Parser panic", FixedVersion: "1.24.5", Reachable: &yes, Symbol: "net/http.ReadRequest", CalledBy: "main.main"},
		{Module: "github.com/BurntSushi/toml", ID: "GHSA-xxxx-yyyy-zzzz", Summary: "Unknown"},
	}
	sb.VulnsChecked = true
	data, err := json.Marshal(sb.OpenVEX())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Context    string `json:"@context"`
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Version    int    `json:"version"`
		Statements []struct {
			Vulnerability struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" || doc.Version != 1 || !strings.HasPrefix(doc.ID, "urn:uuid:") || doc.Author == "" {
		t.Fatalf("header: %+v", doc)
	}
	if len(doc.Statements) != 3 {
		t.Fatalf("statements: %+v", doc.Statements)
	}
	unreachable, reachable, unknown := doc.Statements[0], doc.Statements[1], doc.Statements[2]
	if unreachable.Vulnerability.Name != "CVE-2026-1111" || unreachable.Status != "not_affected" || unreachable.Justification != "vulnerable_code_not_in_execute_path" ||
		!strings.Contains(unreachable.ImpactStatement, "not reachable from any program entrypoint") || len(unreachable.Vulnerability.Aliases) != 2 {
		t.Errorf("unreachable: %+v", unreachable)
	}
	if unreachable.Products[0].ID != "pkg:golang/github.com/acme/shop" || unreachable.Products[0].Subcomponents[0].ID != "pkg:golang/github.com/gin-gonic/gin@v1.10.0" {
		t.Errorf("products: %+v", unreachable.Products)
	}
	if reachable.Status != "affected" || reachable.Justification != "" || !strings.Contains(reachable.ActionStatement, "1.24.5") || !strings.Contains(reachable.ActionStatement, "main.main") {
		t.Errorf("reachable: %+v", reachable)
	}
	if reachable.Products[0].Subcomponents[0].ID != "pkg:golang/stdlib@v1.24.2" {
		t.Errorf("stdlib product: %+v", reachable.Products)
	}
	if unknown.Status != "under_investigation" {
		t.Errorf("unknown: %+v", unknown)
	}

	bom := sb.CycloneDX()
	states := []string{}
	for _, v := range bom.Vulnerabilities {
		states = append(states, v.Analysis.State+"/"+v.Analysis.Justification)
	}
	if strings.Join(states, ",") != "not_affected/code_not_reachable,exploitable/,in_triage/" {
		t.Errorf("CycloneDX analysis: %v", states)
	}
	if bom.Vulnerabilities[0].Affects[0].Ref != "pkg:golang/github.com/gin-gonic/gin@v1.10.0" {
		t.Errorf("affects: %+v", bom.Vulnerabilities[0].Affects)
	}
}
