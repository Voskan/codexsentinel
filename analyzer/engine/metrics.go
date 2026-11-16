package engine

import (
	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/metrics"
)

// runMetricsAnalysis computes the metrics that need the whole workspace, using
// the thresholds from the metrics configuration. Per-file metrics are computed
// with the package rules.
func runMetricsAnalysis(ws *workspace.Workspace, bundle *codessa.GraphBundle, cfg *config.Config) []result.Issue {
	ac := &analyzer.AnalyzerContext{Cfg: cfg, RootDir: ws.RootDir, Fset: ws.Fset}
	for _, issue := range metrics.RunWorkspace(ws, bundle, cfg.Metrics) {
		ac.Report(issue)
	}
	return ac.GetIssues()
}
