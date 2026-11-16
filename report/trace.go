package report

import (
	"fmt"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// TraceLines renders a data-flow trace as numbered human-readable steps,
// e.g. "1. [source] handler.go:18 untrusted input returned by ...".
func TraceLines(trace []result.TraceStep) []string {
	lines := make([]string, 0, len(trace))
	for i, step := range trace {
		loc := step.Location.File
		if step.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, step.Location.Line)
		}
		line := fmt.Sprintf("%d. [%s] %s", i+1, step.Kind, loc)
		if step.Message != "" {
			line += " " + step.Message
		}
		lines = append(lines, line)
	}
	return lines
}

// TraceLines returns the rendered data-flow steps of the issue.
func (i Issue) TraceLines() []string { return TraceLines(i.Trace) }
