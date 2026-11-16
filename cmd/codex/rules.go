package codex

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/Voskan/codexsentinel/analyzer/result"
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
			docs, err := filterRules(category, severity)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch format {
			case "table", "":
				return printRuleTable(out, docs)
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(docs)
			case "markdown", "md":
				printRuleMarkdown(out, docs)
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

func filterRules(category, severity string) ([]catalog.RuleDoc, error) {
	docs := catalog.All()
	if category != "" {
		docs = catalog.ByCategory(category)
		if len(docs) == 0 {
			return nil, fmt.Errorf("unknown category %q", category)
		}
	}
	if severity == "" {
		return docs, nil
	}
	minimum := result.ParseSeverity(severity)
	if minimum == result.SeverityUnknown {
		return nil, fmt.Errorf("unknown severity %q", severity)
	}
	var out []catalog.RuleDoc
	for _, d := range docs {
		if d.DefaultSeverity.GreaterThanOrEqual(minimum) {
			out = append(out, d)
		}
	}
	return out, nil
}

func printRuleTable(w io.Writer, docs []catalog.RuleDoc) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CODE\tID\tSEVERITY\tCATEGORY\tCWE\tFIX\tTITLE")
	for _, d := range docs {
		fix := ""
		if d.HasAutoFix {
			fix = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Code, d.ID, d.DefaultSeverity, d.Category, dash(d.CWE), dash(fix), d.Title)
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func printRuleMarkdown(w io.Writer, docs []catalog.RuleDoc) {
	fmt.Fprintln(w, "| Code | Rule | Severity | Category | CWE | Title |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	for _, d := range docs {
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %s |\n", d.Code, d.ID, d.DefaultSeverity, d.Category, dash(d.CWE), d.Title)
	}
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
				msg := fmt.Sprintf("unknown rule %q", args[0])
				if similar := catalog.Similar(args[0], 3); len(similar) > 0 {
					msg += "; did you mean " + strings.Join(similar, ", ") + "?"
				}
				return fmt.Errorf("%s (run 'codex-cli rules' for the full list)", msg)
			}
			printExplanation(cmd.OutOrStdout(), doc)
			return nil
		},
	}
}

func printExplanation(w io.Writer, d catalog.RuleDoc) {
	fmt.Fprintf(w, "%s  %s\n%s\n\n", d.Code, d.Title, strings.Repeat("=", len(d.Code)+2+len(d.Title)))
	fields := [][2]string{{"ID", d.ID}, {"Severity", string(d.DefaultSeverity)}, {"Category", d.Category}, {"CWE", d.CWE}, {"OWASP", d.OWASP}}
	if d.HasAutoFix {
		fields = append(fields, [2]string{"Autofix", "yes (codex-cli scan --fix)"})
	}
	for _, f := range fields {
		if f[1] != "" {
			fmt.Fprintf(w, "%-9s %s\n", f[0]+":", f[1])
		}
	}
	fmt.Fprintf(w, "\n%s\n\n%s\n", d.Summary, wrap(d.Explanation, 80))
	fmt.Fprintf(w, "\nVulnerable example:\n\n%s\n", indent(d.BadExample))
	fmt.Fprintf(w, "\nSafe pattern:\n\n%s\n", indent(d.GoodExample))
	fmt.Fprintf(w, "\nSuppress a reviewed finding:\n\n    //codex:ignore %s -- <reason>\n", d.ID)
	if len(d.References) > 0 {
		fmt.Fprintln(w, "\nReferences:")
		for _, r := range d.References {
			fmt.Fprintf(w, "  - %s\n", r)
		}
	}
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

// wrap breaks text into lines of at most width characters at spaces.
func wrap(text string, width int) string {
	var b strings.Builder
	n := 0
	for _, word := range strings.Fields(text) {
		if n > 0 && n+1+len(word) > width {
			b.WriteByte('\n')
			n = 0
		} else if n > 0 {
			b.WriteByte(' ')
			n++
		}
		b.WriteString(word)
		n += len(word)
	}
	return b.String()
}
