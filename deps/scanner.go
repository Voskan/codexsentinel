// Package deps provides combined dependency scanning logic for CodexSentinel.
package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DependencyReport aggregates all security and license information per module.
type DependencyReport struct {
	Module        string // e.g. github.com/foo/bar
	Version       string // e.g. v1.2.3
	License       string // e.g. MIT
	LicenseStatus string // ALLOWED / DENIED / UNKNOWN
	LicenseFile   string // path/to/LICENSE

	Vulnerabilities []Vulnerability  // CVE / GHSA results from osv.dev
	SuspiciousFiles []EntropyFinding // High-entropy values in vendored code
}

// ScanDependencies performs full dependency audit:
// - license classification
// - CVE lookup (via osv-scanner)
// - secret-like strings
func ScanDependencies(goModPath string, allowLicenses, denyLicenses []string) ([]DependencyReport, error) {
	modDir := filepath.Dir(goModPath)
	var reports []DependencyReport

	licenses, err := AnalyzeLicenses(goModPath, allowLicenses, denyLicenses)
	if err != nil {
		return nil, fmt.Errorf("license scan failed: %w", err)
	}

	vulns, err := AuditVulnerabilities(goModPath)
	if err != nil {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	// Map CVEs by module@version
	vulnMap := make(map[string][]Vulnerability)
	for _, v := range vulns {
		key := fmt.Sprintf("%s@%s", v.Module, v.Version)
		vulnMap[key] = append(vulnMap[key], v)
	}

	// Scan vendor directory for high-entropy strings
	vendorDir := filepath.Join(modDir, "vendor")
	var entropyFindings []EntropyFinding
	if stat, err := os.Stat(vendorDir); err == nil && stat.IsDir() {
		files := collectGoFiles(vendorDir)
		entropyFindings, _ = AnalyzeHighEntropyStrings(files, 20, 4.2)
	}

	// Group entropy results by module
	entropyMap := make(map[string][]EntropyFinding)
	for _, f := range entropyFindings {
		mod := extractVendorModule(f.File)
		if mod != "" {
			entropyMap[mod] = append(entropyMap[mod], f)
		}
	}

	// Aggregate results
	for _, lic := range licenses {
		key := fmt.Sprintf("%s@%s", lic.Module, lic.Version)

		status := "UNKNOWN"
		if lic.Allowed {
			status = "ALLOWED"
		} else if lic.Denied {
			status = "DENIED"
		}

		reports = append(reports, DependencyReport{
			Module:          lic.Module,
			Version:         lic.Version,
			License:         lic.License,
			LicenseStatus:   status,
			LicenseFile:     lic.LicenseFile,
			Vulnerabilities: vulnMap[key],
			SuspiciousFiles: entropyMap[lic.Module],
		})
	}

	return reports, nil
}

// collectGoFiles recursively collects all .go files from vendor directory.
func collectGoFiles(root string) []string {
	var result []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".go" {
			result = append(result, path)
		}
		return nil
	})
	return result
}

// extractVendorModule tries to extract module name from vendor path.
// e.g. vendor/github.com/foo/bar/file.go → github.com/foo/bar
func extractVendorModule(path string) string {
	path = filepath.ToSlash(path)
	idx := strings.Index(path, "vendor/")
	if idx == -1 {
		return ""
	}
	parts := strings.Split(path[idx+7:], "/")
	if len(parts) >= 3 {
		return strings.Join(parts[0:3], "/")
	}
	return ""
}
