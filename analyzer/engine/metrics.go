package engine

import (
	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"github.com/Voskan/codexsentinel/v2/config"
	"github.com/Voskan/codexsentinel/v2/metrics"
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
