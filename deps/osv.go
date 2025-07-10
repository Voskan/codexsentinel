// Package deps provides audit of known vulnerabilities using osv.dev.
package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Vulnerability represents a CVE or known vulnerability for a Go module.
type Vulnerability struct {
	Module     string `json:"module"`     // Module name (e.g., github.com/foo/bar)
	Version    string `json:"version"`    // Vulnerable version
	ID         string `json:"id"`         // CVE or GHSA ID
	Details    string `json:"details"`    // Description or summary
	Severity   string `json:"severity"`   // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	FixedVersion string `json:"fixed"`    // Version where fixed (if available)
	Aliases    []string `json:"aliases"`  // Alternative IDs
	Reference  string `json:"reference"`  // Reference URL
}

// AuditVulnerabilities runs osv-scanner against the given go.mod path and returns a list of vulnerabilities.
//
// Requires:
//   - Installed `osv-scanner` CLI (https://github.com/google/osv-scanner)
func AuditVulnerabilities(goModPath string) ([]Vulnerability, error) {
	cmd := exec.Command("osv-scanner", "--format", "json", "--lockfile", goModPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run osv-scanner: %w", err)
	}

	var result osvResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse osv output: %w", err)
	}

	var vulns []Vulnerability
	for _, finding := range result.Results {
		for _, vuln := range finding.Vulnerabilities {
			v := Vulnerability{
				Module:     finding.Package.Name,
				Version:    finding.Package.Version,
				ID:         vuln.ID,
				Details:    vuln.Details,
				FixedVersion: extractFixedVersion(vuln.Affected),
				Severity:   extractSeverity(vuln.Severity),
				Aliases:    vuln.Aliases,
				Reference:  vuln.DatabaseSpecific.URL,
			}
			vulns = append(vulns, v)
		}
	}

	return vulns, nil
}

// osvResult represents the top-level JSON structure returned by osv-scanner.
type osvResult struct {
	Results []struct {
		Package struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"package"`
		Vulnerabilities []struct {
			ID                string   `json:"id"`
			Details           string   `json:"details"`
			Aliases           []string `json:"aliases"`
			Severity          []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Introduced string `json:"introduced,omitempty"`
						Fixed      string `json:"fixed,omitempty"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
			DatabaseSpecific struct {
				URL string `json:"url"`
			} `json:"database_specific"`
		} `json:"vulnerabilities"`
	} `json:"results"`
}

// extractFixedVersion attempts to extract the first fixed version from the affected list.
func extractFixedVersion(affected []struct {
	Ranges []struct {
		Events []struct {
			Introduced string `json:"introduced,omitempty"`
			Fixed      string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
}) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// extractSeverity attempts to extract the highest severity score.
func extractSeverity(sev []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range sev {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return s.Score
		}
	}
	return ""
}
