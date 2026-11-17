package codex

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/deps"
	"github.com/spf13/cobra"
)

const defaultCapsLockfile = ".codexsentinel.caps.json"

// NewCapsCmd returns the `caps` command that inspects, locks and verifies the
// capabilities exercised by dependency modules.
func NewCapsCmd() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:   "caps",
		Short: "Inspect, lock and verify dependency capabilities",
	}
	cmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to a custom config file")

	inspect := &cobra.Command{
		Use:   "inspect [path]",
		Short: "Show the capabilities each dependency uses from reachable code",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, _, err := capabilityReport(cmd.Context(), targetArg(args), configFile)
			if err != nil {
				return err
			}
			printCapabilities(cmd.OutOrStdout(), report)
			return nil
		},
	}

	var out string
	lock := &cobra.Command{
		Use:   "lock [path]",
		Short: "Write the current dependency capabilities to a lock file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, root, err := capabilityReport(cmd.Context(), targetArg(args), configFile)
			if err != nil {
				return err
			}
			path := resolveLockfile(root, out)
			if err := deps.WriteCapabilityLock(path, report.Lock()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote capabilities of %d modules to %s\n", len(report.Modules), path)
			return nil
		},
	}
	lock.Flags().StringVar(&out, "out", defaultCapsLockfile, "Lock file to write")

	var lockfile string
	verify := &cobra.Command{
		Use:   "verify [path]",
		Short: "Fail when a dependency gained capabilities missing from the lock file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, issues, err := verifyCapabilities(cmd.Context(), targetArg(args), configFile, lockfile)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if len(issues) == 0 {
				fmt.Fprintf(w, "No capability escalations against %s\n", path)
				return nil
			}
			for _, issue := range issues {
				fmt.Fprintf(w, "[%s] %s\n", issue.Severity, issue.Description)
			}
			return &IssuesFoundError{Count: len(issues)}
		},
	}
	verify.Flags().StringVar(&lockfile, "lockfile", defaultCapsLockfile, "Lock file to verify against")

	cmd.AddCommand(inspect, lock, verify)
	return cmd
}

func targetArg(args []string) string {
	if len(args) > 0 {
		return normalizeTargetPath(args[0])
	}
	return "."
}

func resolveLockfile(root, path string) string {
	if path == "" {
		path = defaultCapsLockfile
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

// capabilityReport loads the module at target and analyzes its dependencies.
func capabilityReport(ctx context.Context, target, configFile string) (*deps.CapabilityReport, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ws, bundle, err := loadProgram(ctx, target, configFile)
	if err != nil {
		return nil, "", err
	}
	report, err := deps.AnalyzeCapabilities(ws, bundle)
	return report, ws.RootDir, err
}

// verifyCapabilities compares the capabilities of the module's dependencies
// with the lock file and returns the lock file path and one finding per
// escalation.
func verifyCapabilities(ctx context.Context, target, configFile, lockfile string) (string, []result.Issue, error) {
	report, root, err := capabilityReport(ctx, target, configFile)
	if err != nil {
		return "", nil, err
	}
	path := resolveLockfile(root, lockfile)
	locked, err := deps.LoadCapabilityLock(path)
	if err != nil {
		return path, nil, fmt.Errorf("read capability lock: %w", err)
	}
	return path, deps.EscalationIssues(deps.DiffCapabilities(locked, report), path), nil
}

func printCapabilities(w io.Writer, report *deps.CapabilityReport) {
	if len(report.Modules) == 0 {
		fmt.Fprintln(w, "No dependency code is reachable.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MODULE\tVERSION\tCAPABILITIES")
	for _, m := range report.Modules {
		caps := make([]string, len(m.Capabilities))
		for i, c := range m.Capabilities {
			caps[i] = string(c)
		}
		list := strings.Join(caps, ", ")
		if list == "" {
			list = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Module, m.Version, list)
	}
	_ = tw.Flush()
	for _, m := range report.Modules {
		for _, c := range m.Capabilities {
			if ev := m.Evidence[c]; ev != "" {
				fmt.Fprintf(w, "  %s %s: %s\n", m.Module, c, ev)
			}
		}
	}
}
