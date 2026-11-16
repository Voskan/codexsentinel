package yaml

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// RuleYAML defines a pattern-based rule loaded from a YAML file.
type RuleYAML struct {
	ID          string   `yaml:"id" json:"id"`                               // Unique rule identifier
	Title       string   `yaml:"title" json:"title"`                         // Human-readable name
	Category    string   `yaml:"category" json:"category"`                   // Rule category (e.g., "security", "style")
	Severity    string   `yaml:"severity" json:"severity"`                   // Severity level (LOW, MEDIUM, HIGH, CRITICAL)
	Description string   `yaml:"description" json:"description"`             // Detailed explanation
	Suggestion  string   `yaml:"suggestion" json:"suggestion"`               // Suggested fix
	References  []string `yaml:"references" json:"references"`               // Optional reference links
	CWE         string   `yaml:"cwe,omitempty" json:"cwe,omitempty"`         // Optional CWE identifier
	Enabled     *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"` // Whether this rule is active

	// Pattern is Go code with metavariables, e.g. "template.HTML($X)".
	Pattern string `yaml:"pattern" json:"pattern"`
	// Fix replaces the matched code; metavariables are substituted with the
	// source text they matched, e.g. "strings.ReplaceAll($S, $OLD, $NEW)".
	Fix string `yaml:"fix,omitempty" json:"fix,omitempty"`

	// Match configuration (pattern and filters).
	Match *MatchConfig `yaml:"match,omitempty" json:"match"`

	Tags []string `yaml:"tags,omitempty" json:"tags"` // Tags for filtering and classification
}

// MatchConfig defines the matching configuration for a rule.
type MatchConfig struct {
	Pattern string `yaml:"pattern" json:"pattern"` // Code pattern to match
	// NotPattern lists patterns that suppress a match when found inside it.
	NotPattern StringList `yaml:"not_pattern,omitempty" json:"not_pattern,omitempty"`
	Filters    []Filter   `yaml:"filters,omitempty" json:"filters"` // Filters to apply
}

// Filter restricts where a pattern match is reported.
//
//   - import: the file imports one of Include.
//   - package: the package name or path matches Allow (if set) and not Exclude.
//   - type: metavariable Var has one of the types in Include, e.g. "*database/sql.DB".
//   - non_const: metavariable Var is not a compile-time constant.
//   - regex: the source text of Var matches one of Include and none of Exclude.
type Filter struct {
	Type    string   `yaml:"type" json:"type"`
	Var     string   `yaml:"var,omitempty" json:"var,omitempty"`
	Include []string `yaml:"include,omitempty" json:"include"`
	Allow   []string `yaml:"allow,omitempty" json:"allow"`
	Exclude []string `yaml:"exclude,omitempty" json:"exclude"`
	// Sources is accepted for backward compatibility and ignored.
	Sources []string `yaml:"sources,omitempty" json:"sources"`
}

// StringList accepts either a single string or a list of strings.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = StringList{node.Value}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		*s = list
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list of strings", node.Line)
}

// IsEnabled defaults omitted settings to enabled.
func (r RuleYAML) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }
