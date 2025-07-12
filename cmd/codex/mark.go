package codex

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// NewMarkCmd returns the `mark` command to manually annotate false-positives.
func NewMarkCmd() *cobra.Command {
	var reason string
	var severity string

	cmd := &cobra.Command{
		Use:   "mark <filepath>[:line]",
		Short: "Manually mark a finding as safe or false-positive",
		Long: `Allows marking a file or specific line as verified/safe (false-positive),
so it can be excluded from future scans or noted in audit logs.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			return markSafe(target, reason, severity)
		},
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "false-positive", "Reason for marking the finding")
	cmd.Flags().StringVarP(&severity, "severity", "s", "", "Optional severity level (info/warning/critical)")

	return cmd
}

// markSafe adds a manual annotation to a file or specific line as safe.
func markSafe(target, reason, severity string) error {
	entry := fmt.Sprintf("MARKED: %s | reason: %s", target, reason)
	if severity != "" {
		entry += fmt.Sprintf(" | severity: %s", strings.ToUpper(severity))
	}

	// Write to known file (e.g., .codexsafe) or audit log
	file, err := os.OpenFile(".codexsafe", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open .codexsafe: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(entry + "\n"); err != nil {
		return fmt.Errorf("failed to write mark: %w", err)
	}

	fmt.Printf("✔ Marked as safe: %s\n", target)
	return nil
}
