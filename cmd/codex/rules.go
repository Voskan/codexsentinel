package codex

import (
	"encoding/json"
	"fmt"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/spf13/cobra"
)

// NewRulesCmd returns the `rules` command, which lists the rule catalog.
func NewRulesCmd() *cobra.Command {
	var category, severity, format string
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List all rules with their code, severity, category and CWE",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			docs, err := catalog.Filter(category, severity)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch format {
			case "table", "":
				return catalog.WriteTable(out, docs)
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(docs)
			case "markdown", "md":
				catalog.WriteMarkdownTable(out, docs)
				return nil
			}
			return fmt.Errorf("unknown format %q (want table, json or markdown)", format)
		},
	}
	cmd.Flags().StringVar(&category, "category", "", "Only rules of this category (security, reliability, supply-chain, architecture, metrics, license, suppression)")
	cmd.Flags().StringVar(&severity, "severity", "", "Only rules at or above this default severity")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json or markdown")
	return cmd
}

// NewExplainCmd returns the `explain` command, which prints one rule's documentation.
func NewExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <rule-id-or-code>",
		Short: "Explain a rule with a vulnerable and a fixed example",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, ok := catalog.Lookup(args[0])
			if !ok {
				return catalog.UnknownRuleError(args[0])
			}
			catalog.WriteCard(cmd.OutOrStdout(), doc)
			return nil
		},
	}
}
