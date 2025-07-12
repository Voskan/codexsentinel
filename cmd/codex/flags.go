package codex

import (
	"github.com/spf13/pflag"
)

// Flags defines all global flags used by the Codex CLI.
type Flags struct {
	Format         string // Output format: json, html, markdown, sarif
	OutputPath     string // Optional path to write report
	EnableAST      bool   // Enable AST-based rule analysis
	EnableSSA      bool   // Enable SSA-based analysis
	EnableTaint    bool   // Enable taint tracking
	IgnoreFile     string // Path to .codexignore file
	DisableBuiltin bool   // Disable built-in rules
}

// Bind binds the Flags to a provided FlagSet.
func (f *Flags) Bind(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Format, "format", "f", "json", "Output format: json, html, markdown, sarif")
	flags.StringVarP(&f.OutputPath, "out", "o", "", "Optional output file path (default: stdout)")
	flags.BoolVar(&f.EnableAST, "ast", true, "Enable AST-based rule analysis")
	flags.BoolVar(&f.EnableSSA, "ssa", true, "Enable SSA-based analysis")
	flags.BoolVar(&f.EnableTaint, "taint", true, "Enable taint tracking")
	flags.StringVar(&f.IgnoreFile, "ignore-file", ".codexignore", "Path to ignore file (default: .codexignore)")
	flags.BoolVar(&f.DisableBuiltin, "no-builtin", false, "Disable built-in rules")
}
