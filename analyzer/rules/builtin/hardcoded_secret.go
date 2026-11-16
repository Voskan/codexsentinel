package builtin

import (
	"fmt"
	"go/token"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/secrets"
)

var hardcodedSecretMeta = ruleMeta{ID: "hardcoded-secret", Title: "Hardcoded Secret", Severity: result.SeverityHigh, CWE: "CWE-798", OWASP: "A07:2025", Confidence: 0.8,
	Suggestion: "Load the secret from the environment or a secret manager at run time and rotate the exposed value.",
	References: []string{"https://cwe.mitre.org/data/definitions/798.html"}}

// span is a source range used as a report anchor.
type span struct{ pos, end token.Pos }

func (s span) Pos() token.Pos { return s.pos }
func (s span) End() token.Pos { return s.end }

// RegisterHardcodedSecretRule reports credentials embedded in source files.
func RegisterHardcodedSecretRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{hardcodedSecretMeta}, func(r *reporter) {
		for _, file := range r.pass.Files {
			for _, f := range secrets.ScanFile(r.pass.Fset, file) {
				meta := hardcodedSecretMeta
				meta.Confidence = f.Confidence
				severity := result.SeverityHigh
				desc := fmt.Sprintf("String assigned to '%s' looks like a hardcoded %s (%s).", f.Name, f.Kind, f.Value)
				if f.Level == secrets.LevelPattern {
					severity = result.SeverityCritical
					desc = fmt.Sprintf("Hardcoded %s found (%s).", f.Kind, f.Value)
				}
				r.reportWith(meta, span{f.Pos, f.End}, desc, severity, nil)
			}
		}
	})
}
