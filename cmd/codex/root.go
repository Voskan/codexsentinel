package codex

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewRootCmd returns the root command of the CLI application.
func NewRootCmd(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "codex-cli",
		Short:         "CodexSentinel - Static code and dependency security scanner",
		Long:          `CodexSentinel finds security vulnerabilities, architecture violations, code quality problems and risky dependencies in Go modules.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.SetContext(ctx)
	cmd.AddCommand(
		NewScanCmd(),
		NewVersionCmd(),
		NewMarkCmd(),
		NewCapsCmd(),
		NewBaselineCmd(),
		NewCacheCmd(),
		NewSBOMCmd(),
	)

	cmd.PersistentFlags().SortFlags = false
	cmd.SetHelpCommand(&cobra.Command{Hidden: true}) // disable default help command

	// Set custom flag error handling
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		c.Usage()
		return fmt.Errorf("flag error: %w", err)
	})

	// Handle unknown commands gracefully
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		c.Usage()
	})

	// Pre-run validation if needed
	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		normalizeFlags(cmd.Flags())
	}

	return cmd
}

// normalizeFlags makes flags more consistent (e.g., handling `--flag=value` vs `--flag value`)
func normalizeFlags(flags *pflag.FlagSet) {
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed && f.Value.Type() == "string" && f.Value.String() == "" {
			flags.Set(f.Name, "")
		}
	})
}

// Execute is the main entry point that runs the root command.
func Execute(ctx context.Context) {
	rootCmd := NewRootCmd(ctx)
	if err := rootCmd.Execute(); err != nil {
		var issuesErr *IssuesFoundError
		if !errors.As(err, &issuesErr) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}
