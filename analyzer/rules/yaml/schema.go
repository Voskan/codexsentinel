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

	Pattern    string   `yaml:"pattern" json:"pattern"`                 // Code pattern to match (e.g., template.Execute($INPUT))
	Source     string   `yaml:"source,omitempty" json:"source"`         // Optional taint source (e.g., req.FormValue)
	Sink       string   `yaml:"sink,omitempty" json:"sink"`             // Optional sink target (e.g., db.Exec)
	Conditions []string `yaml:"conditions,omitempty" json:"conditions"` // Optional logical conditions
	MatchFile  string   `yaml:"matchFile,omitempty" json:"matchFile"`   // Optional filename pattern
	Tags       []string `yaml:"tags,omitempty" json:"tags"`             // Tags for filtering and classification
}
