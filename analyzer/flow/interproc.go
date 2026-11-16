package flow

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// SinkHit records a parameter-rooted flow into a sink inside a function.
type SinkHit struct {
	Category string
	Sink     *SinkSpec
	Pos      token.Pos
	Fn       *ssa.Function
	Steps    []Step
}

// FuncSummary describes the taint behaviour of a function for its callers.
type FuncSummary struct {
	ParamToSink map[int][]SinkHit
}

func newSummary() *FuncSummary {
	return &FuncSummary{ParamToSink: map[int][]SinkHit{}}
}

func (s *FuncSummary) addSinkHit(param int, hit SinkHit) {
	s.ParamToSink[param] = append(s.ParamToSink[param], hit)
}

func (s *FuncSummary) fromState(st *funcState) {}

func (a *analysis) runInterprocedural() {
	for _, fn := range a.bundle.TargetFunctions() {
		if fn.Parent() == nil {
			a.analyze(fn)
		}
	}
}

func (a *analysis) applySummaries(s *funcState, instr ssa.CallInstruction, recv ssa.Value, args []ssa.Value) bool {
	return false
}
