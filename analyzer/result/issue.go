package result

import (
	"fmt"
	"strings"
)

type TraceStep struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
	Kind     string   `json:"kind"`
}

type TextEdit struct {
	File        string `json:"file"`
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
	StartOffset int    `json:"startOffset"`
	EndOffset   int    `json:"endOffset"`
	NewText     string `json:"newText"`
}

type SuggestedFix struct {
	Message string     `json:"message"`
	Edits   []TextEdit `json:"edits"`
}

type Issue struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    Severity      `json:"severity"`
	Confidence  float64       `json:"confidence,omitempty"`
	CWE         string        `json:"cwe,omitempty"`
	OWASP       string        `json:"owasp,omitempty"`
	Location    Location      `json:"location"`
	Category    string        `json:"category"`
	Suggestion  string        `json:"suggestion"`
	References  []string      `json:"references,omitempty"`
	Trace       []TraceStep   `json:"trace,omitempty"`
	Fix         *SuggestedFix `json:"fix,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Reachable   *bool         `json:"reachable,omitempty"`
	FalsePos    bool          `json:"falsePositive,omitempty"`
	Ignored     bool          `json:"ignored,omitempty"`
}

// String returns a concise human-readable summary of the issue.
func (i Issue) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("[%s] %s\n", i.Severity.Colored(), i.Title))
	sb.WriteString(fmt.Sprintf("   └─ ID:        %s\n", i.ID))
	sb.WriteString(fmt.Sprintf("   └─ Category:  %s\n", i.Category))
	sb.WriteString(fmt.Sprintf("   └─ Location:  %s\n", i.Location.String()))
	if i.Suggestion != "" {
		sb.WriteString(fmt.Sprintf("   └─ Fix:       %s\n", i.Suggestion))
	}
	return sb.String()
}

// IsSecurity returns true if the issue is of security-related category.
func (i Issue) IsSecurity() bool {
	return strings.EqualFold(i.Category, "security")
}

// IsCritical returns true if severity is CRITICAL.
func (i Issue) IsCritical() bool {
	return i.Severity == SeverityCritical
}

// IsIgnored returns true if the issue is manually ignored or marked as false positive.
func (i Issue) IsIgnored() bool {
	return i.Ignored || i.FalsePos
}
