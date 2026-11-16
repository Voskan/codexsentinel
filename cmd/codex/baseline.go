package codex

import (
	"fmt"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/baseline"
	"github.com/Voskan/codexsentinel/internal/logx"
	"github.com/spf13/cobra"
)

// NewBaselineCmd returns the `baseline` command that records the current
// findings so that later scans with --baseline report only new ones.
func NewBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage the baseline of accepted findings",
	}
	var out, configFile string
	create := &cobra.Command{
		Use:   "create [path]",
		Short: "Scan the project and record all current findings in a baseline file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			return createBaseline(cmd, normalizeTargetPath(target), out, configFile)
		},
	}
	create.Flags().StringVar(&out, "out", baseline.DefaultFile, "Path of the baseline file to write")
	create.Flags().StringVar(&configFile, "config", "", "Path to a custom config file")
	cmd.AddCommand(create)
	return cmd
}

func createBaseline(cmd *cobra.Command, target, out, configFile string) error {
	if err := logx.Init(true); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logx.Sync()
	logger := logx.L()
	cfg, err := loadConfig(configFile, logger)
	if err != nil {
		return err
	}
	results, err := runFullAnalysis(cmd.Context(), target, "", cfg, "", logger)
	if err != nil {
		return err
	}
	b := baseline.New(results, time.Now())
	if err := b.Write(out); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Recorded %d findings in %s\n", len(b.Entries), out)
	return nil
}
