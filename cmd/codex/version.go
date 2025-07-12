package codex

import (
	"fmt"
	"runtime"

	"github.com/Voskan/codexsentinel/internal/version"
	"github.com/spf13/cobra"
)

// NewVersionCmd returns the `version` command.
func NewVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the current version of CodexSentinel",
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()
		},
	}
	return cmd
}

// printVersion prints detailed version information to stdout.
func printVersion() {
	fmt.Printf("CodexSentinel version: %s\n", version.Version)
	fmt.Printf("Commit: %s\n", version.Commit)
	fmt.Printf("Build date: %s\n", version.BuildDate)
	fmt.Printf("Go version: %s\n", runtime.Version())
}
