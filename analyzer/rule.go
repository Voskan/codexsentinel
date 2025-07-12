package analyzer

import (
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

type Rule struct {
	ID       string
	Title    string
	Category string
	Severity result.Severity
	Summary  string
	Matcher  func(*AnalyzerContext, *analysis.Pass)
}
