package yaml

// RuleYAML defines the structure of a YAML-based rule.
// These rules can be loaded from external .yaml files.
type RuleYAML struct {
	ID          string   `yaml:"id" json:"id"`                   // Unique rule identifier
	Title       string   `yaml:"title" json:"title"`             // Human-readable name
	Category    string   `yaml:"category" json:"category"`       // Rule category (e.g., "security", "style")
	Severity    string   `yaml:"severity" json:"severity"`       // Severity level (LOW, MEDIUM, HIGH, CRITICAL)
	Description string   `yaml:"description" json:"description"` // Detailed explanation
	Suggestion  string   `yaml:"suggestion" json:"suggestion"`   // Suggested fix
	References  []string `yaml:"references" json:"references"`   // Optional reference links
	Enabled     bool     `yaml:"enabled" json:"enabled"`         // Whether this rule is active

	// Pattern matching
	Pattern string `yaml:"pattern" json:"pattern"` // Code pattern to match (e.g., template.Execute($INPUT))

	// Match configuration
	Match *MatchConfig `yaml:"match,omitempty" json:"match"` // Match configuration

	// Legacy fields for backward compatibility
	Source     string   `yaml:"source,omitempty" json:"source"`         // Optional taint source (e.g., req.FormValue)
	Sink       string   `yaml:"sink,omitempty" json:"sink"`             // Optional sink target (e.g., db.Exec)
	Conditions []string `yaml:"conditions,omitempty" json:"conditions"` // Optional logical conditions
	MatchFile  string   `yaml:"matchFile,omitempty" json:"matchFile"`   // Optional filename pattern
	Tags       []string `yaml:"tags,omitempty" json:"tags"`             // Tags for filtering and classification
}

// MatchConfig defines the matching configuration for a rule
type MatchConfig struct {
	Pattern string   `yaml:"pattern" json:"pattern"`           // Code pattern to match
	Filters []Filter `yaml:"filters,omitempty" json:"filters"` // Filters to apply
}

// Filter defines a filter for rule matching
type Filter struct {
	Type    string   `yaml:"type" json:"type"`                 // Filter type: param, call, import, file_ext, package
	Sources []string `yaml:"sources,omitempty" json:"sources"` // Sources for param/call filters
	Include []string `yaml:"include,omitempty" json:"include"` // Include patterns
	Allow   []string `yaml:"allow,omitempty" json:"allow"`     // Allow patterns
	Exclude []string `yaml:"exclude,omitempty" json:"exclude"` // Exclude patterns
}

// Examples provides good and bad code examples
type Examples struct {
	Bad  string `yaml:"bad" json:"bad"`   // Bad code example
	Good string `yaml:"good" json:"good"` // Good code example
}
