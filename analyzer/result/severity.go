package result

import (
	"fmt"
	"strings"
)

// Severity represents the level of importance or impact of an issue.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
	SeverityUnknown  Severity = "UNKNOWN"
)

// AllSeverities returns the full list of valid severity levels in order.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

// ParseSeverity parses a string into a Severity value. Falls back to SeverityUnknown.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "INFO":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// SeverityColor returns the ANSI color code associated with the severity.
func SeverityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "\033[1;35m" // Magenta
	case SeverityHigh:
		return "\033[1;31m" // Red
	case SeverityMedium:
		return "\033[1;33m" // Yellow
	case SeverityLow:
		return "\033[1;34m" // Blue
	case SeverityInfo:
		return "\033[0;36m" // Cyan
	default:
		return "\033[0m" // Reset
	}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// Compare returns -1 if s < other, 0 if s == other, 1 if s > other
func (s Severity) Compare(other Severity) int {
	severityOrder := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
		SeverityUnknown:  0,
	}

	sOrder := severityOrder[s]
	otherOrder := severityOrder[other]

	if sOrder < otherOrder {
		return -1
	} else if sOrder > otherOrder {
		return 1
	}
	return 0
}

// GreaterThanOrEqual returns true if s >= other
func (s Severity) GreaterThanOrEqual(other Severity) bool {
	return s.Compare(other) >= 0
}

// Colored returns the colored string of severity for CLI output.
func (s Severity) Colored() string {
	return fmt.Sprintf("%s%s\033[0m", SeverityColor(s), s)
}
