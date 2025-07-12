package yaml

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/rules"
	"github.com/go-yaml/yaml"
)

// LoadFromDir loads all YAML rule files from the given directory.
func LoadFromDir(dir string) error {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		return loadFile(path)
	})
	if err != nil {
		return fmt.Errorf("error loading rules from directory %q: %w", dir, err)
	}
	return nil
}

// loadFile reads and parses a single YAML rule file.
func loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %q: %w", path, err)
	}

	var rule RuleYAML
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("failed to parse YAML in %q: %w", path, err)
	}

	if rule.ID == "" {
		return fmt.Errorf("invalid rule in %q: missing required field 'id'", path)
	}

	// Determine pattern from match config or legacy pattern field
	pattern := rule.Pattern
	if rule.Match != nil && rule.Match.Pattern != "" {
		pattern = rule.Match.Pattern
	}
	if pattern == "" {
		return fmt.Errorf("invalid rule in %q: missing required field 'pattern' or 'match.pattern'", path)
	}

	// Create YAML rule with pattern and filters
	yamlRule := &rules.YAMLRule{
		Pattern: pattern,
		Filters: make(map[string]string),
	}

	// Process filters if match config exists
	if rule.Match != nil {
		for _, filter := range rule.Match.Filters {
			switch filter.Type {
			case "param":
				for _, source := range filter.Sources {
					yamlRule.Filters["param_"+source] = "true"
				}
			case "call":
				for _, source := range filter.Sources {
					yamlRule.Filters["call_"+source] = "true"
				}
			case "file_ext":
				for _, ext := range filter.Include {
					yamlRule.Filters["file_ext_"+ext] = "true"
				}
			case "package":
				for _, pkg := range filter.Allow {
					yamlRule.Filters["package_"+pkg] = "true"
				}
			}
		}
	}

	// Set default values
	if rule.Enabled == false {
		rule.Enabled = true // Default to enabled
	}
	if rule.Category == "" {
		rule.Category = "security" // Default category
	}
	if rule.Severity == "" {
		rule.Severity = "MEDIUM" // Default severity
	}

	// Register into global rule registry
	return rules.Register(&rules.Rule{
		ID:          rule.ID,
		Title:       rule.Title,
		Category:    rule.Category,
		Severity:    rule.Severity,
		Description: rule.Description,
		Suggestion:  rule.Suggestion,
		References:  rule.References,
		YAML:        yamlRule,
		Enabled:     rule.Enabled,
		Engine:      createYAMLRuleEngine(rule), // Create engine function for YAML rule
	})
}

// createYAMLRuleEngine creates a rule engine function for YAML-based rules
func createYAMLRuleEngine(rule RuleYAML) rules.RuleFunc {
	return func(ctx *analyzer.AnalyzerContext) ([]result.Issue, error) {
		var issues []result.Issue

		// This is a placeholder implementation
		// In a real implementation, you would:
		// 1. Parse the pattern using AST
		// 2. Apply filters
		// 3. Match against the code
		// 4. Generate issues

		// For now, create a simple issue to demonstrate
		if rule.Enabled {
			issues = append(issues, result.Issue{
				ID:          rule.ID,
				Title:       rule.Title,
				Description: rule.Description,
				Severity:    result.ParseSeverity(rule.Severity),
				Location:    result.NewLocationFromPos(ctx.GetFset().Position(0), ctx.Filename, ""),
				Category:    rule.Category,
				Suggestion:  rule.Suggestion,
			})
		}

		return issues, nil
	}
}
