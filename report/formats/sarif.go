package formats

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Voskan/codexsentinel/report"
)

// sarifReport defines the structure of a SARIF output file.
type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool sarifTool   `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	FullName       string         `json:"fullName"`
	Version        string         `json:"version"`
	InformationURI string         `json:"informationUri"`
	Rules          []sarifRule    `json:"rules"`
}

type sarifRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ShortDesc   sarifText `json:"shortDescription"`
	FullDesc    sarifText `json:"fullDescription"`
	HelpURI     string `json:"helpUri,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID string `json:"ruleId"`
	Message sarifText `json:"message"`
	Locations []sarifLocation `json:"locations"`
	Level string `json:"level"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIFReport converts the internal issues into SARIF format and writes to file.
func WriteSARIFReport(issues []report.Issue, path string) error {
	tool := sarifTool{
		Driver: sarifDriver{
			Name:           "CodexSentinel",
			FullName:       "CodexSentinel Static Analysis Tool",
			Version:        "1.0.0",
			InformationURI: "https://github.com/Voskan/codexsentinel",
			Rules:          []sarifRule{},
		},
	}

	results := make([]sarifResult, 0, len(issues))
	ruleMap := map[string]sarifRule{}

	for _, i := range issues {
		level := severityToLevel(i.Severity)

		result := sarifResult{
			RuleID: i.RuleID,
			Message: sarifText{Text: i.Description},
			Level: level,
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: i.File},
					Region: sarifRegion{StartLine: i.Line},
				},
			}},
		}
		results = append(results, result)

		// If rule is not yet added to the driver rules list
		if _, exists := ruleMap[i.RuleID]; !exists {
			ruleMap[i.RuleID] = sarifRule{
				ID: i.RuleID,
				Name: i.Title,
				ShortDesc: sarifText{Text: i.Title},
				FullDesc: sarifText{Text: i.Description},
				HelpURI: i.Reference,
				Properties: map[string]string{
					"severity": string(i.Severity),
					"suggestion": i.Suggestion,
				},
			}
		}
	}

	for _, rule := range ruleMap {
		tool.Driver.Rules = append(tool.Driver.Rules, rule)
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: tool,
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// severityToLevel converts internal severity into SARIF level.
func severityToLevel(sev report.SeverityLevel) string {
	switch sev {
	case report.SeverityCritical, report.SeverityHigh:
		return "error"
	case report.SeverityMedium:
		return "warning"
	case report.SeverityLow, report.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
