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

// LoadFromFile loads a single YAML rule file.
func LoadFromFile(path string) error {
	return loadFile(path)
}

// loadFile reads and parses a single YAML rule file.
func loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %q: %w", path, err)
	}

	rule, err := parseRuleYAML(data, path)
	if err != nil {
		return err
	}

	if err := validateRule(rule, path); err != nil {
		return err
	}

	yamlRule := createYAMLRule(rule)
	setDefaultValues(rule)

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
		Engine:      createYAMLRuleEngine(*rule), // Create engine function for YAML rule
	})
}

// parseRuleYAML parses YAML data into a RuleYAML struct
func parseRuleYAML(data []byte, path string) (*RuleYAML, error) {
	var rule RuleYAML
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %q: %w", path, err)
	}
	return &rule, nil
}

// validateRule validates the rule structure
func validateRule(rule *RuleYAML, path string) error {
	if rule.ID == "" {
		return fmt.Errorf("invalid rule in %q: missing required field 'id'", path)
	}

	pattern := getRulePattern(rule)
	if pattern == "" {
		return fmt.Errorf("invalid rule in %q: missing required field 'pattern' or 'match.pattern'", path)
	}

	return nil
}

// getRulePattern extracts the pattern from rule configuration
func getRulePattern(rule *RuleYAML) string {
	pattern := rule.Pattern
	if rule.Match != nil && rule.Match.Pattern != "" {
		pattern = rule.Match.Pattern
	}
	return pattern
}

// createYAMLRule creates a YAMLRule with pattern and filters
func createYAMLRule(rule *RuleYAML) *rules.YAMLRule {
	yamlRule := &rules.YAMLRule{
		Pattern: getRulePattern(rule),
		Filters: make(map[string]string),
	}

	if rule.Match != nil {
		processFilters(rule.Match.Filters, yamlRule.Filters)
	}

	return yamlRule
}

// processFilters processes match filters and adds them to the filters map
func processFilters(filters []Filter, filtersMap map[string]string) {
	for _, filter := range filters {
		switch filter.Type {
		case "param":
			processParamFilter(filter, filtersMap)
		case "call":
			processCallFilter(filter, filtersMap)
		case "file_ext":
			processFileExtFilter(filter, filtersMap)
		case "package":
			processPackageFilter(filter, filtersMap)
		}
	}
}

// processParamFilter processes parameter filters
func processParamFilter(filter Filter, filtersMap map[string]string) {
	for _, source := range filter.Sources {
		filtersMap["param_"+source] = "true"
	}
}

// processCallFilter processes call filters
func processCallFilter(filter Filter, filtersMap map[string]string) {
	for _, source := range filter.Sources {
		filtersMap["call_"+source] = "true"
	}
}

// processFileExtFilter processes file extension filters
func processFileExtFilter(filter Filter, filtersMap map[string]string) {
	for _, ext := range filter.Include {
		filtersMap["file_ext_"+ext] = "true"
	}
}

// processPackageFilter processes package filters
func processPackageFilter(filter Filter, filtersMap map[string]string) {
	for _, pkg := range filter.Allow {
		filtersMap["package_"+pkg] = "true"
	}
}

// setDefaultValues sets default values for rule fields
func setDefaultValues(rule *RuleYAML) {
	if !rule.Enabled {
		rule.Enabled = true // Default to enabled
	}
	if rule.Category == "" {
		rule.Category = "security" // Default category
	}
	if rule.Severity == "" {
		rule.Severity = "MEDIUM" // Default severity
	}
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
