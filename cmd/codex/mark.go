package codex

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// NewMarkCmd returns the command for recording a finding suppression.
func NewMarkCmd() *cobra.Command {
	var reason, rule, ignoreFile string
	cmd := &cobra.Command{
		Use:   "mark <filepath[:line]>",
		Short: "Ignore a finding in future scans",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return markSafe(args[0], rule, reason, ignoreFile)
		},
	}
	cmd.Flags().StringVar(&rule, "rule", "", "Rule ID to ignore")
	cmd.Flags().StringVarP(&reason, "reason", "r", "false-positive", "Reason for ignoring the finding")
	cmd.Flags().StringVar(&ignoreFile, "ignore-file", ".codexsentinel.ignore", "Path to ignore file")
	_ = cmd.MarkFlagRequired("rule")
	return cmd
}

func markSafe(target, rule, reason, ignoreFile string) error {
	if target == "" || rule == "" || strings.ContainsAny(target+rule, " \t\r\n#") || strings.ContainsAny(reason, "\r\n") {
		return fmt.Errorf("target and rule must be nonempty single tokens, and reason must be one line")
	}
	if i := strings.LastIndex(target, ":"); i >= 0 {
		line, err := strconv.Atoi(target[i+1:])
		if err != nil || line <= 0 || i == 0 {
			return fmt.Errorf("invalid file:line target: %s", target)
		}
	}
	data, err := os.ReadFile(ignoreFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read ignore file: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 2 && fields[0] == target && fields[1] == rule {
			return nil
		}
	}
	entry := fmt.Sprintf("%s %s # %s\n", target, rule, reason)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		entry = "\n" + entry
	}
	file, err := os.OpenFile(ignoreFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open ignore file: %w", err)
	}
	if _, err = file.WriteString(entry); err != nil {
		file.Close()
		return fmt.Errorf("write suppression: %w", err)
	}
	return file.Close()
}
