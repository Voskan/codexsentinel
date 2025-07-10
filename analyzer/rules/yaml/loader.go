package yaml

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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

	if rule.ID == "" || rule.Pattern == "" {
		return fmt.Errorf("invalid rule in %q: missing required fields 'id' or 'pattern'", path)
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
		YAML:        &rule,
		Enabled:     rule.Enabled,
	})
}
