// Package config provides configuration loading and default merging for CodexSentinel.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFilename is the expected name of the configuration file.
const DefaultConfigFilename = ".codex.yml"

// Load loads the CodexSentinel configuration from the given file.
// If the file is not found or invalid, returns default config with an optional warning.
func Load(path string) (Config, error) {
	cfg := DefaultConfig

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist: fallback to default config
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// LoadDefaultPath loads configuration from the default file name (.codex.yml).
func LoadDefaultPath() (Config, error) {
	return Load(DefaultConfigFilename)
}

// LoadFromPath loads configuration from a specific file path and returns a pointer.
func LoadFromPath(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadDefaultPathPtr loads configuration from the default file name and returns a pointer.
func LoadDefaultPathPtr() (*Config, error) {
	cfg, err := LoadDefaultPath()
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
