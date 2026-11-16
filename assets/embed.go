// Package assets holds the files compiled into the codex-cli binary.
package assets

import "embed"

// BuiltinRulesFS holds the default YAML rule files under rules/. They are
// embedded so that the rules apply wherever the binary runs, not only inside
// this repository.
//
//go:embed rules/*.yaml
var BuiltinRulesFS embed.FS
