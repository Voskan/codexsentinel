package formats

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/report"
)

// GitLabCodeQualityIssue is one entry of a GitLab Code Quality report, the
// CodeClimate issue format that merge request widgets display.
type GitLabCodeQualityIssue struct {
	Type        string         `json:"type"`
	EngineName  string         `json:"engine_name"`
	Description string         `json:"description"`
	CheckName   string         `json:"check_name"`
	Fingerprint string         `json:"fingerprint"`
	Severity    string         `json:"severity"`
	Categories  []string       `json:"categories,omitempty"`
	Location    GitLabIssueLoc `json:"location"`
}

// GitLabIssueLoc is the location of a Code Quality issue.
type GitLabIssueLoc struct {
	Path  string          `json:"path"`
	Lines GitLabIssueLine `json:"lines"`
}

// GitLabIssueLine is the first line of a Code Quality issue.
type GitLabIssueLine struct {
	Begin int `json:"begin"`
}

// WriteGitLabReport writes a GitLab Code Quality report (a JSON array; empty
// results are written as []).
func WriteGitLabReport(issues []report.Issue, outPath string, _ *report.GitMetadata) error {
	data, err := json.MarshalIndent(GitLabCodeQuality(issues), "", "  ")
	if err != nil {
		return err
	}
	return writeOutput(outPath, append(data, '\n'))
}

// GitLabCodeQuality converts issues to Code Quality entries.
func GitLabCodeQuality(issues []report.Issue) []GitLabCodeQualityIssue {
	out := make([]GitLabCodeQualityIssue, 0, len(issues))
	for _, is := range sortedIssues(issues) {
		desc := is.Title
		if is.Description != "" {
			desc += ": " + is.Description
		}
		if is.CWE != "" {
			desc += " (" + is.CWE + ")"
		}
		out = append(out, GitLabCodeQualityIssue{
			Type:        "issue",
			EngineName:  "codexsentinel",
			Description: desc,
			CheckName:   is.RuleID,
			Fingerprint: gitlabFingerprint(is),
			Severity:    gitlabSeverity(is.Severity),
			Categories:  []string{gitlabCategory(is)},
			Location:    GitLabIssueLoc{Path: gitlabPath(is), Lines: GitLabIssueLine{Begin: max(is.Line, 1)}},
		})
	}
	return out
}

func gitlabSeverity(s report.SeverityLevel) string {
	switch s {
	case report.SeverityCritical:
		return "blocker"
	case report.SeverityHigh:
		return "critical"
	case report.SeverityMedium:
		return "major"
	case report.SeverityLow:
		return "minor"
	}
	return "info"
}

// gitlabCategory maps finding categories to CodeClimate categories.
func gitlabCategory(is report.Issue) string {
	switch is.Category {
	case "reliability":
		return "Bug Risk"
	case "architecture":
		return "Complexity"
	case "metrics":
		if is.RuleID == "code-duplication" {
			return "Duplication"
		}
		return "Complexity"
	case "license":
		return "Compatibility"
	}
	return "Security"
}

// gitlabPath returns the slash-separated relative path GitLab expects.
// Findings without a file are attached to go.mod when they concern
// dependencies, otherwise to the repository root.
func gitlabPath(is report.Issue) string {
	p := strings.ReplaceAll(is.File, `\`, "/")
	if p == "" {
		if is.Category == "supply-chain" || is.Category == "license" {
			return "go.mod"
		}
		return "."
	}
	p = path.Clean(p)
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

func gitlabFingerprint(is report.Issue) string {
	if is.Fingerprint != "" {
		return is.Fingerprint
	}
	sum := sha256.Sum256([]byte(is.RuleID + "\x00" + is.File + "\x00" + strconv.Itoa(is.Line) + "\x00" + is.Description))
	return hex.EncodeToString(sum[:])
}
