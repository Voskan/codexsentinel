package codex

import (
	"os"
	"path/filepath"

	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"github.com/Voskan/codexsentinel/v2/config"
)

// loadedConfig is the configuration of one command run together with where
// it came from.
type loadedConfig struct {
	*config.Config
	// Path is the configuration file, or "" when the defaults are used.
	Path string
	// Root is the module root of the target.
	Root string
}

// loadTargetConfig loads the configuration for a command that analyzes
// target. An explicit configFile wins. Otherwise the first default
// configuration file (.codexsentinel.yaml, .codexsentinel.yml, codex.yaml,
// .codex.yml) is used from the target's module root or one of its parents up
// to the repository root, so a monorepo can keep one configuration at the
// top. When cwdFallback is set, the working directory is tried last.
//
// Relative rule_paths and rule_files are resolved against the directory of
// the configuration file, so the scan finds them from any working directory.
func loadTargetConfig(target, configFile string, cwdFallback bool) (*loadedConfig, error) {
	root, err := workspace.ProjectRoot(target)
	if err != nil {
		return nil, err
	}
	path := configFile
	if path == "" {
		path = findConfigFrom(root)
	}
	if path == "" && cwdFallback {
		path = config.FindDefaultConfigFile(".")
	}
	if path == "" {
		cfg := config.NewDefaultConfig()
		return &loadedConfig{Config: &cfg, Root: root}, nil
	}
	cfg, err := config.LoadFromPath(path)
	if err != nil {
		return nil, err
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	base := filepath.Dir(path)
	cfg.Rules.RulePaths = resolveAll(base, cfg.Rules.RulePaths)
	cfg.Rules.RuleFiles = resolveAll(base, cfg.Rules.RuleFiles)
	return &loadedConfig{Config: cfg, Path: path, Root: root}, nil
}

// findConfigFrom looks for a default configuration file in dir and its
// parents, stopping at the directory that contains .git.
func findConfigFrom(dir string) string {
	for {
		if path := config.FindDefaultConfigFile(dir); path != "" {
			return path
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func resolveAll(base string, paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		if p != "" && !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		out[i] = p
	}
	return out
}
