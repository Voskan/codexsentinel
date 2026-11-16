package formats

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/version"
	"github.com/Voskan/codexsentinel/report"
)

// sarifReport defines the structure of a SARIF 2.1.0 log.
type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	FullName       string      `json:"fullName"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	ShortDesc  sarifText      `json:"shortDescription"`
	FullDesc   sarifText      `json:"fullDescription"`
	Help       *sarifText     `json:"help,omitempty"`
	HelpURI    string         `json:"helpUri,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	CodeFlows           []sarifCodeFlow   `json:"codeFlows,omitempty"`
	Fixes               []sarifFix        `json:"fixes,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifText            `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
	Kinds    []string      `json:"kinds,omitempty"`
}

type sarifFix struct {
	Description     sarifText             `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion `json:"deletedRegion"`
	InsertedContent sarifText   `json:"insertedContent"`
}

// BuildSARIF converts issues into a SARIF 2.1.0 log.
func BuildSARIF(issues []report.Issue, gitMeta *report.GitMetadata) ([]byte, error) {
	results := make([]sarifResult, 0, len(issues))
	ruleMap := map[string]sarifRule{}
	for _, i := range issues {
		res := sarifResult{
			RuleID:    i.RuleID,
			Level:     severityToLevel(i.Severity),
			Message:   sarifText{Text: firstNonEmpty(i.Description, i.Title)},
			Locations: []sarifLocation{physical(i.File, i.Line, i.Column, i.EndLine, i.EndColumn, "")},
		}
		if len(i.Trace) > 0 {
			flow := sarifThreadFlow{}
			for _, step := range i.Trace {
				loc := physical(step.Location.File, step.Location.Line, step.Location.Column, step.Location.EndLine, step.Location.EndColumn, step.Message)
				tfl := sarifThreadFlowLocation{Location: loc}
				if step.Kind != "" {
					tfl.Kinds = []string{step.Kind}
				}
				flow.Locations = append(flow.Locations, tfl)
			}
			res.CodeFlows = []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{flow}}}
		}
		if i.Fix != nil && len(i.Fix.Edits) > 0 {
			res.Fixes = []sarifFix{toSARIFFix(i.Fix)}
		}
		if i.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"codexsentinel/v1": i.Fingerprint}
		}
		props := map[string]any{}
		if i.Confidence > 0 {
			props["confidence"] = i.Confidence
		}
		if i.Category != "" {
			props["category"] = i.Category
		}
		if i.Reachable != nil {
			props["reachable"] = *i.Reachable
		}
		if len(props) > 0 {
			res.Properties = props
		}
		results = append(results, res)

		if _, exists := ruleMap[i.RuleID]; !exists {
			rule := sarifRule{
				ID:        i.RuleID,
				Name:      firstNonEmpty(i.Title, i.RuleID),
				ShortDesc: sarifText{Text: firstNonEmpty(i.Title, i.RuleID)},
				FullDesc:  sarifText{Text: firstNonEmpty(i.Description, i.Title, i.RuleID)},
				HelpURI:   i.Reference,
			}
			if i.Suggestion != "" {
				rule.Help = &sarifText{Text: i.Suggestion}
			}
			ruleProps := map[string]any{"problem.severity": severityToLevel(i.Severity)}
			var tags []string
			if i.Category != "" {
				tags = append(tags, i.Category)
			}
			if i.CWE != "" {
				tags = append(tags, "external/cwe/"+i.CWE)
			}
			if i.OWASP != "" {
				tags = append(tags, "owasp/"+i.OWASP)
			}
			if len(tags) > 0 {
				ruleProps["tags"] = tags
			}
			if score, ok := securitySeverity[i.Severity]; ok && i.Category == "security" {
				ruleProps["security-severity"] = score
			}
			rule.Properties = ruleProps
			ruleMap[i.RuleID] = rule
		}
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(a, b int) bool { return rules[a].ID < rules[b].ID })

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "CodexSentinel",
			FullName:       "CodexSentinel Static Analysis Tool",
			Version:        version.Version,
			InformationURI: "https://github.com/Voskan/codexsentinel",
			Rules:          rules,
		}},
		Results: results,
	}
	if props := gitProperties(gitMeta); len(props) > 0 {
		run.Properties = props
	}
	log := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{run},
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF report: %w", err)
	}
	return data, nil
}

// WriteSARIFReport converts the internal issues into SARIF format and writes to file.
func WriteSARIFReport(issues []report.Issue, path string, gitMeta *report.GitMetadata) error {
	data, err := BuildSARIF(issues, gitMeta)
	if err != nil {
		return err
	}
	return writeOutput(path, data)
}

var securitySeverity = map[report.SeverityLevel]string{
	report.SeverityCritical: "9.5",
	report.SeverityHigh:     "8.0",
	report.SeverityMedium:   "5.5",
	report.SeverityLow:      "3.0",
	report.SeverityInfo:     "1.0",
}

func physical(file string, line, column, endLine, endColumn int, message string) sarifLocation {
	if line < 1 {
		line = 1
	}
	region := sarifRegion{StartLine: line}
	if column > 0 {
		region.StartColumn = column
	}
	if endLine >= line {
		region.EndLine = endLine
		if endColumn > 0 {
			region.EndColumn = endColumn
		}
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(file)}, Region: region}}
	if message != "" {
		loc.Message = &sarifText{Text: message}
	}
	return loc
}

func toSARIFFix(fix *result.SuggestedFix) sarifFix {
	byFile := map[string][]sarifReplacement{}
	var order []string
	for _, e := range fix.Edits {
		if _, ok := byFile[e.File]; !ok {
			order = append(order, e.File)
		}
		byFile[e.File] = append(byFile[e.File], sarifReplacement{
			DeletedRegion:   sarifRegion{StartLine: e.StartLine, StartColumn: e.StartColumn, EndLine: e.EndLine, EndColumn: e.EndColumn},
			InsertedContent: sarifText{Text: e.NewText},
		})
	}
	out := sarifFix{Description: sarifText{Text: fix.Message}}
	for _, file := range order {
		out.ArtifactChanges = append(out.ArtifactChanges, sarifArtifactChange{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(file)}, Replacements: byFile[file]})
	}
	return out
}

func gitProperties(gitMeta *report.GitMetadata) map[string]any {
	props := map[string]any{}
	if gitMeta == nil {
		return props
	}
	if gitMeta.RepoRoot != "" {
		props["repository"] = gitMeta.RepoRoot
	}
	if gitMeta.Branch != "" {
		props["branch"] = gitMeta.Branch
	}
	if gitMeta.CommitHash != "" {
		props["commit"] = gitMeta.CommitHash
	}
	if gitMeta.IsDirty {
		props["dirty"] = true
	}
	return props
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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
