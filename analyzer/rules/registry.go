package rules

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

// RuleFunc defines the function signature for Go-based rules.
type RuleFunc func(ctx *analyzer.AnalyzerContext) ([]result.Issue, error)

// YAMLRule represents a YAML-based rule definition.
type YAMLRule struct {
	Pattern string            `yaml:"pattern"`
	Filters map[string]string `yaml:"filters,omitempty"`
}

// Rule represents metadata and behavior for a registered rule.
type Rule struct {
	ID          string    // Unique rule ID (e.g., "sql-injection")
	Title       string    // Human-readable title
	Category    string    // Category (e.g., "security", "style", "performance")
	Severity    string    // Severity level (e.g., "HIGH", "LOW")
	Description string    // Detailed description
	Suggestion  string    // Suggested fix
	References  []string  // External documentation links
	Engine      RuleFunc  // Optional Go-based rule implementation
	YAML        *YAMLRule // Optional YAML-based definition
	Enabled     bool      // If the rule is enabled
	// Fingerprint identifies the rule definition, for example a hash of its
	// YAML source. Results of rules without one are not cached.
	Fingerprint string
}

var (
	rulesMu sync.RWMutex
	rules   = make(map[string]*Rule)
)

// Register registers a rule into the global registry.
func Register(r *Rule) error {
	rulesMu.Lock()
	defer rulesMu.Unlock()

	if r.ID == "" {
		return errors.New("rule ID cannot be empty")
	}
	if _, exists := rules[r.ID]; exists {
		return fmt.Errorf("rule with ID '%s' already registered", r.ID)
	}

	rules[r.ID] = r
	return nil
}

// Upsert registers r, replacing any rule already registered with the same ID.
// Loading the same rule files again is therefore harmless, which long-running
// processes rely on.
func Upsert(r *Rule) error {
	if r == nil || r.ID == "" {
		return errors.New("rule ID cannot be empty")
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules[r.ID] = r
	return nil
}

// Get returns a rule by its ID.
func Get(id string) (*Rule, bool) {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	rule, ok := rules[id]
	return rule, ok
}

// All returns all registered rules.
func All() []*Rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()

	all := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		all = append(all, r)
	}
	return all
}

// EnabledRules returns only rules that are marked as enabled.
func EnabledRules() []*Rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()

	filtered := make([]*Rule, 0)
	for _, r := range rules {
		if r.Enabled {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// Clear removes all registered rules (used in tests or reload).
func Clear() {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules = make(map[string]*Rule)
}
