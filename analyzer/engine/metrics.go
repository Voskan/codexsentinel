package engine

import (
	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/metrics"
)

// runMetricsAnalysis computes code quality metrics once for the whole workspace,
// using the thresholds from the metrics configuration.
func runMetricsAnalysis(ws *workspace.Workspace, bundle *codessa.GraphBundle, cfg *config.Config) []result.Issue {
	ac := &analyzer.AnalyzerContext{Cfg: cfg, RootDir: ws.RootDir, Fset: ws.Fset}
	for _, issue := range metrics.Run(ws, bundle, cfg.Metrics) {
		ac.Report(issue)
	}
	return ac.GetIssues()
}
