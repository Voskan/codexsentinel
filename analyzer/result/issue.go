package result

import (
	"fmt"
	"strings"
)

// Issue represents a single detected vulnerability, warning or code smell.
type Issue struct {
	ID          string   `json:"id"`            // Unique identifier of the rule (e.g., "sql-injection")
	Title       string   `json:"title"`         // Short title of the issue
	Description string   `json:"description"`   // Detailed description of the issue
	Severity    Severity `json:"severity"`      // Issue severity
	Location    Location `json:"location"`      // Where the issue was found
	Category    string   `json:"category"`      // Category (security, performance, style, etc.)
	Suggestion  string   `json:"suggestion"`    // Suggested fix
	References  []string `json:"references"`    // Links to documentation or references
	FalsePos    bool     `json:"falsePositive"` // Marked as false positive (optional)
	Ignored     bool     `json:"ignored"`       // Manually ignored via CLI or config
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
