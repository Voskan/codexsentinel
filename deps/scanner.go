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
	
	// A06:2025 - Additional fields for vulnerable and outdated components
	IsOutdated     bool   // Component is outdated
	LatestVersion  string // Latest available version
	UpdateStatus   string // UPDATE_AVAILABLE / UP_TO_DATE / DEPRECATED
	DeprecationMsg string // Deprecation warning if applicable
	SecurityScore  int    // Security score (0-100)
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

	// Fetch additional advisories from GitHub Advisory Database
	ghsaVulns, err := FetchGHSAAdvisories(goModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GHSA fetch error: %v\n", err)
	} else {
		// Merge, avoiding duplicates by Module+ID
		existing := make(map[string]struct{})
		for _, v := range vulns {
			existing[v.Module+"/"+v.ID] = struct{}{}
		}
		for _, v := range ghsaVulns {
			key := v.Module+"/"+v.ID
			if _, ok := existing[key]; !ok {
				vulns = append(vulns, v)
			}
		}
	}

	// Map CVEs by module@version
	vulnMap := make(map[string][]Vulnerability)
	for _, v := range vulns {
		// Skip stdlib vulnerabilities as they're not in go.mod
		if v.Module == "stdlib" {
			continue
		}
		
		// Normalize version by removing 'v' prefix if present
		normalizedVersion := strings.TrimPrefix(v.Version, "v")
		
		key := fmt.Sprintf("%s@%s", v.Module, normalizedVersion)
		vulnMap[key] = append(vulnMap[key], v)
	}

	// Scan vendor directory for high-entropy strings
	vendorDir := filepath.Join(modDir, "vendor")
	var entropyFindings []EntropyFinding
	if stat, err := os.Stat(vendorDir); err == nil && stat.IsDir() {
		files := collectGoFiles(vendorDir)
		entropyFindings, err = AnalyzeHighEntropyStrings(files, 20, 4.2)
	if err != nil {
		// Log error but continue with analysis
		fmt.Printf("Warning: entropy analysis failed: %v\n", err)
	}
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
		// Normalize version by removing 'v' prefix if present
		normalizedVersion := strings.TrimPrefix(lic.Version, "v")
		
		key := fmt.Sprintf("%s@%s", lic.Module, normalizedVersion)

		status := "UNKNOWN"
		if lic.Allowed {
			status = "ALLOWED"
		} else if lic.Denied {
			status = "DENIED"
		}

		report := DependencyReport{
			Module:          lic.Module,
			Version:         lic.Version,
			License:         lic.License,
			LicenseStatus:   status,
			LicenseFile:     lic.LicenseFile,
			Vulnerabilities: vulnMap[key],
			SuspiciousFiles: entropyMap[lic.Module],
		}
		
		reports = append(reports, report)
	}

	return reports, nil
}

// collectGoFiles recursively collects all .go files from vendor directory.
func collectGoFiles(root string) []string {
	var result []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".go" {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Warning: failed to walk directory %s: %v\n", root, err)
	}
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
