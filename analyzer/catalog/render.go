package catalog

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// UnknownRuleError describes a rule that is not in the catalog and suggests
// similar IDs.
func UnknownRuleError(query string) error {
	msg := fmt.Sprintf("unknown rule %q", query)
	if similar := Similar(query, 3); len(similar) > 0 {
		msg += "; did you mean " + strings.Join(similar, ", ") + "?"
	}
	return fmt.Errorf("%s (run 'codex-cli rules' for the full list)", msg)
}

// Filter returns the rules of a category (all when empty) whose default
// severity is at or above severity (any when empty).
func Filter(category, severity string) ([]RuleDoc, error) {
	docs := All()
	if category != "" {
		docs = ByCategory(category)
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
	out := []RuleDoc{}
	for _, d := range docs {
		if d.DefaultSeverity.GreaterThanOrEqual(minimum) {
			out = append(out, d)
		}
	}
	return out, nil
}

// WriteTable writes docs as an aligned table.
func WriteTable(w io.Writer, docs []RuleDoc) error {
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

// WriteMarkdownTable writes docs as a Markdown table.
func WriteMarkdownTable(w io.Writer, docs []RuleDoc) {
	fmt.Fprintln(w, "| Code | Rule | Severity | Category | CWE | Title |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	for _, d := range docs {
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %s |\n", d.Code, d.ID, d.DefaultSeverity, d.Category, dash(d.CWE), d.Title)
	}
}

// WriteCard writes the full documentation of one rule as plain text.
func WriteCard(w io.Writer, d RuleDoc) {
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
	fmt.Fprintf(w, "\nDocumentation: %s\n", DocURL(d.ID))
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
