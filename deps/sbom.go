package deps

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

// SBOMComponent is one module of a software bill of materials.
type SBOMComponent struct {
	Module   string
	Version  string
	Indirect bool
	License  string // SPDX identifier, or "" when unknown
	// GoSum is the h1: hash of the module content from go.sum.
	GoSum        string
	Capabilities []Capability
	Evidence     map[Capability]string
}

// SBOM describes a module and its dependencies. It is rendered as
// CycloneDX, SPDX or OpenVEX.
type SBOM struct {
	Root        string // module path from go.mod
	Components  []SBOMComponent
	Vulns       []Vulnerability
	Timestamp   time.Time
	ToolName    string
	ToolVersion string
	// Vulnerabilities were looked up; when false the vulnerability sections
	// are left out.
	VulnsChecked bool
}

// ReadSBOM collects the modules required by goModPath with their go.sum
// hashes. Modules replaced by local directories are left out, as they have
// no published version. The standard library is included when go.mod names
// a Go version.
func ReadSBOM(goModPath string) (*SBOM, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}
	mods, err := ReadGoMod(goModPath)
	if err != nil {
		return nil, err
	}
	sums, err := readSumHashes(filepath.Join(filepath.Dir(goModPath), "go.sum"))
	if err != nil {
		return nil, err
	}
	sb := &SBOM{Timestamp: time.Now().UTC()}
	if f.Module != nil {
		sb.Root = f.Module.Mod.Path
	}
	for _, m := range mods {
		sb.Components = append(sb.Components, SBOMComponent{
			Module: m.Path, Version: m.Version, Indirect: m.Indirect, GoSum: sums[m.Path+" "+m.Version],
		})
	}
	sort.SliceStable(sb.Components, func(i, j int) bool { return sb.Components[i].Module < sb.Components[j].Module })
	return sb, nil
}

// readSumHashes maps "path version" to the h1: content hash in go.sum.
func readSumHashes(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 3 && strings.HasPrefix(fields[2], "h1:") && !strings.HasSuffix(fields[1], "/go.mod") {
			out[fields[0]+" "+fields[1]] = fields[2]
		}
	}
	return out, sc.Err()
}

// SetLicenses records the SPDX identifiers found by AnalyzeLicenses.
func (s *SBOM) SetLicenses(findings []LicenseFinding) {
	byModule := map[string]string{}
	for _, f := range findings {
		if f.License != "" && f.License != "UNKNOWN" {
			byModule[f.Module] = f.License
		}
	}
	for i := range s.Components {
		if lic, ok := byModule[s.Components[i].Module]; ok {
			s.Components[i].License = lic
		}
	}
}

// SetCapabilities records the capabilities of each module.
func (s *SBOM) SetCapabilities(report *CapabilityReport) {
	if report == nil {
		return
	}
	for i := range s.Components {
		if m, ok := report.Module(s.Components[i].Module); ok {
			s.Components[i].Capabilities = m.Capabilities
			s.Components[i].Evidence = m.Evidence
		}
	}
}

// SHA256FromGoSum decodes an h1: go.sum hash into hex. The hash is the
// SHA-256 of the module's file list and file hashes.
func SHA256FromGoSum(h1 string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h1, "h1:"))
	if !strings.HasPrefix(h1, "h1:") || err != nil || len(raw) != sha256.Size {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// PURL returns the package URL of a Go module version, for example
// pkg:golang/github.com/gin-gonic/gin@v1.10.0. The standard library is
// pkg:golang/stdlib@v1.24.2.
func PURL(module, version string) string {
	if module == StdlibModule && version != "" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	segments := strings.Split(module, "/")
	for i, seg := range segments {
		segments[i] = purlEscape(seg)
	}
	out := "pkg:golang/" + strings.Join(segments, "/")
	if version != "" {
		out += "@" + purlEscape(version)
	}
	return out
}

func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// rootPURL identifies the scanned module itself.
func (s *SBOM) rootPURL() string { return PURL(s.Root, "") }

// deterministicUUID derives a version 4 style UUID from the content, so the
// same input yields the same identifier.
func deterministicUUID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *SBOM) identity() []string {
	parts := []string{s.Root, s.ToolVersion}
	for _, c := range s.Components {
		parts = append(parts, c.Module+"@"+c.Version)
	}
	for _, v := range s.Vulns {
		parts = append(parts, v.Module+"/"+v.ID)
	}
	return parts
}

// CycloneDX types, limited to the fields this tool fills in.

// CycloneDXBOM is a CycloneDX 1.6 JSON document.
type CycloneDXBOM struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        CDXMetadata        `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Dependencies    []CDXDependency    `json:"dependencies"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"`
}

type CDXMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     CDXTools     `json:"tools"`
	Component CDXComponent `json:"component"`
}

type CDXTools struct {
	Components []CDXComponent `json:"components"`
}

type CDXComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Scope      string        `json:"scope,omitempty"`
	Hashes     []CDXHash     `json:"hashes,omitempty"`
	Licenses   []CDXLicense  `json:"licenses,omitempty"`
	Properties []CDXProperty `json:"properties,omitempty"`
}

type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type CDXLicense struct {
	License CDXLicenseID `json:"license"`
}

type CDXLicenseID struct {
	ID string `json:"id"`
}

type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type CDXVulnerability struct {
	BOMRef      string      `json:"bom-ref"`
	ID          string      `json:"id"`
	Source      *CDXSource  `json:"source,omitempty"`
	References  []CDXVulRef `json:"references,omitempty"`
	Ratings     []CDXRating `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Advisories  []CDXAdvice `json:"advisories,omitempty"`
	Analysis    CDXAnalysis `json:"analysis"`
	Affects     []CDXAffect `json:"affects"`
}

type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type CDXVulRef struct {
	ID     string    `json:"id"`
	Source CDXSource `json:"source"`
}

type CDXRating struct {
	Severity string `json:"severity"`
}

type CDXAdvice struct {
	URL string `json:"url"`
}

type CDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type CDXAffect struct {
	Ref string `json:"ref"`
}

// CycloneDX renders the bill of materials as CycloneDX 1.6.
func (s *SBOM) CycloneDX() *CycloneDXBOM {
	root := CDXComponent{Type: "application", BOMRef: s.rootPURL(), Name: s.Root, PURL: s.rootPURL()}
	bom := &CycloneDXBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		SerialNumber: "urn:uuid:" + deterministicUUID(s.identity()...),
		Metadata: CDXMetadata{
			Timestamp: s.Timestamp.UTC().Format(time.RFC3339),
			Tools:     CDXTools{Components: []CDXComponent{{Type: "application", Name: s.toolName(), Version: s.ToolVersion}}},
			Component: root,
		},
		Components: []CDXComponent{},
	}
	rootDep := CDXDependency{Ref: root.BOMRef}
	refs := map[string]string{}
	for _, c := range s.Components {
		comp := CDXComponent{Type: "library", Name: c.Module, Version: c.Version, PURL: PURL(c.Module, c.Version), Scope: "required"}
		comp.BOMRef = comp.PURL
		refs[c.Module] = comp.BOMRef
		if hexSum, ok := SHA256FromGoSum(c.GoSum); ok {
			comp.Hashes = []CDXHash{{Alg: "SHA-256", Content: hexSum}}
			comp.Properties = append(comp.Properties, CDXProperty{Name: "go:sum", Value: c.GoSum})
		}
		if c.License != "" {
			comp.Licenses = []CDXLicense{{License: CDXLicenseID{ID: c.License}}}
		}
		if c.Indirect {
			comp.Properties = append(comp.Properties, CDXProperty{Name: "go:indirect", Value: "true"})
		}
		for _, capability := range c.Capabilities {
			comp.Properties = append(comp.Properties, CDXProperty{Name: "codexsentinel:capability", Value: string(capability)})
			if ev := c.Evidence[capability]; ev != "" {
				comp.Properties = append(comp.Properties, CDXProperty{Name: "codexsentinel:capability:evidence:" + string(capability), Value: ev})
			}
		}
		bom.Components = append(bom.Components, comp)
		rootDep.DependsOn = append(rootDep.DependsOn, comp.BOMRef)
		bom.Dependencies = append(bom.Dependencies, CDXDependency{Ref: comp.BOMRef})
	}
	bom.Dependencies = append([]CDXDependency{rootDep}, bom.Dependencies...)
	if s.VulnsChecked {
		bom.Vulnerabilities = []CDXVulnerability{}
		for _, v := range s.Vulns {
			bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVulnerability(v, refs[v.Module]))
		}
	}
	return bom
}

func (s *SBOM) toolName() string {
	if s.ToolName != "" {
		return s.ToolName
	}
	return "codexsentinel"
}

func cdxVulnerability(v Vulnerability, ref string) CDXVulnerability {
	out := CDXVulnerability{
		BOMRef: v.Module + "/" + v.ID, ID: v.ID, Description: v.Summary,
		Source:  &CDXSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
		Affects: []CDXAffect{{Ref: ref}},
	}
	if strings.HasPrefix(v.ID, "GHSA-") && v.Reference != "" {
		out.Source = &CDXSource{Name: "GitHub", URL: v.Reference}
	}
	if sev := strings.ToLower(v.Severity); sev != "" {
		out.Ratings = []CDXRating{{Severity: sev}}
	}
	for _, a := range v.Aliases {
		out.References = append(out.References, CDXVulRef{ID: a, Source: CDXSource{Name: aliasSource(a)}})
	}
	if v.Reference != "" {
		out.Advisories = []CDXAdvice{{URL: v.Reference}}
	}
	switch {
	case v.Reachable != nil && !*v.Reachable:
		out.Analysis = CDXAnalysis{State: "not_affected", Justification: "code_not_reachable", Detail: notReachableStatement(v)}
	case v.Reachable != nil:
		out.Analysis = CDXAnalysis{State: "exploitable", Response: []string{"update"}, Detail: actionStatement(v)}
	default:
		out.Analysis = CDXAnalysis{State: "in_triage"}
	}
	return out
}

func aliasSource(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "NVD"
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub"
	case strings.HasPrefix(id, "GO-"):
		return "Go Vulnerability Database"
	}
	return "OSV"
}

// SPDX types for an SPDX 2.3 JSON document.

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []SPDXChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// SPDX renders the bill of materials as SPDX 2.3.
func (s *SBOM) SPDX() *SPDXDocument {
	rootID := "SPDXRef-Package-" + spdxIDPart(s.Root)
	doc := &SPDXDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: s.Root,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + spdxIDPart(s.Root) + "-" + deterministicUUID(s.identity()...),
		CreationInfo:      SPDXCreationInfo{Created: s.Timestamp.UTC().Format(time.RFC3339), Creators: []string{"Tool: " + s.toolName() + "-" + s.ToolVersion}},
		Packages: []SPDXPackage{{
			Name: s.Root, SPDXID: rootID, DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
			ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: s.rootPURL()}},
		}},
		Relationships: []SPDXRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: rootID}},
	}
	for _, c := range s.Components {
		id := "SPDXRef-Package-" + spdxIDPart(c.Module+"-"+c.Version)
		lic := "NOASSERTION"
		if c.License != "" {
			lic = c.License
		}
		pkg := SPDXPackage{
			Name: c.Module, SPDXID: id, VersionInfo: c.Version, DownloadLocation: "NOASSERTION",
			LicenseConcluded: "NOASSERTION", LicenseDeclared: lic, CopyrightText: "NOASSERTION",
			ExternalRefs: []SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: PURL(c.Module, c.Version)}},
		}
		if hexSum, ok := SHA256FromGoSum(c.GoSum); ok {
			pkg.Checksums = []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: hexSum}}
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, SPDXRelationship{SPDXElementID: rootID, RelationshipType: "DEPENDS_ON", RelatedSPDXElement: id})
	}
	return doc
}

// spdxIDPart keeps the characters SPDX allows in identifiers.
func spdxIDPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
