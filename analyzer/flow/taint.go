package flow

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// TaintEngine performs taint flow analysis from source to sink.
type TaintEngine struct {
	Sources  *SourceRegistry
	Sinks    *SinkRegistry
	Issues   []TaintIssue
	position token.Positioner
}

// TaintIssue represents a detected source-to-sink flow.
type TaintIssue struct {
	SourcePos token.Pos
	SinkPos   token.Pos
	Source    string
	Sink      string
	Trace     []token.Pos
}

// NewTaintEngine creates a new TaintEngine instance.
func NewTaintEngine(sources *SourceRegistry, sinks *SinkRegistry, pos token.Positioner) *TaintEngine {
	return &TaintEngine{
		Sources:  sources,
		Sinks:    sinks,
		position: pos,
	}
}

// AnalyzeFunction analyzes a single function for taint flows.
func (t *TaintEngine) AnalyzeFunction(fn *ssa.Function) {
	if fn == nil || fn.Blocks == nil {
		return
	}

	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			t.analyzeInstruction(instr)
		}
	}
}

// analyzeInstruction checks SSA instruction for taint flow.
func (t *TaintEngine) analyzeInstruction(instr ssa.Instruction) {
	call, ok := instr.(ssa.CallInstruction)
	if !ok {
		return
	}

	callExpr := call.Common()
	if callExpr == nil || callExpr.Value == nil {
		return
	}

	// Match sink function
	sinkFn := callExpr.StaticCallee()
	if sinkFn == nil {
		return
	}

	sinkSig := sinkFn.Signature
	if sinkSig == nil {
		return
	}

	sinkName := sinkFn.String()
	sink := t.matchSink(sinkName)
	if sink == nil {
		return
	}

	// Check if any argument is tainted
	for _, idx := range sink.MatchArgs {
		if idx >= len(callExpr.Args) {
			continue
		}
		arg := callExpr.Args[idx]

		if t.isTainted(arg) {
			t.Issues = append(t.Issues, TaintIssue{
				Source:    t.findSource(arg),
				Sink:      sinkName,
				SourcePos: arg.Pos(),
				SinkPos:   instr.Pos(),
				Trace:     []token.Pos{arg.Pos(), instr.Pos()},
			})
		}
	}
}

// matchSink finds a registered sink by full function name.
func (t *TaintEngine) matchSink(name string) *Sink {
	for _, s := range t.Sinks.All() {
		if nameHasSuffix(name, s.Package+"."+s.Function) {
			return &s
		}
	}
	return nil
}

// isTainted checks if an SSA value originates from a taint source.
func (t *TaintEngine) isTainted(val ssa.Value) bool {
	// Simple heuristic: check for argument, free variable, or call from known source
	switch v := val.(type) {
	case *ssa.Parameter:
		return t.Sources.MatchParameter(v)
	case *ssa.Call:
		return t.Sources.MatchCall(v)
	default:
		return false
	}
}

// findSource returns a source label for the tainted value.
func (t *TaintEngine) findSource(val ssa.Value) string {
	switch v := val.(type) {
	case *ssa.Parameter:
		return "param:" + v.Name()
	case *ssa.Call:
		return "call:" + v.Call.String()
	default:
		return "unknown"
	}
}

// nameHasSuffix checks if full name ends with expected suffix.
func nameHasSuffix(name, suffix string) bool {
	return len(name) >= len(suffix) && name[len(name)-len(suffix):] == suffix
}
