package flow

import (
	"fmt"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// SinkHit records a parameter-rooted flow into a sink inside a function.
type SinkHit struct {
	Category string
	Sink     *SinkSpec
	Pos      token.Pos
	Fn       *ssa.Function
	// Steps is the trace from the parameter to the sink.
	Steps []Step
}

// ParamFlow describes how a parameter reaches a result or another parameter.
type ParamFlow struct {
	Sanitized map[string]bool
	Steps     []Step
}

// FuncSummary describes the taint behaviour of a function for its callers.
// Parameter indexes follow ssa.Function.Params, so a method receiver is 0.
type FuncSummary struct {
	// SourceReturns holds source taint the function returns by itself.
	SourceReturns *Node
	// ParamToReturn maps a parameter to the taint it contributes to the results.
	ParamToReturn map[int]ParamFlow
	// ParamToSink maps a parameter to the sinks it reaches unsanitized.
	ParamToSink map[int][]SinkHit
	// SourceToParam holds source taint written through a pointer parameter.
	SourceToParam map[int]*Node
	// ParamToParam maps (from, to) parameters for writes through pointers.
	ParamToParam map[[2]int]ParamFlow
}

func newSummary() *FuncSummary {
	return &FuncSummary{
		ParamToReturn: map[int]ParamFlow{},
		ParamToSink:   map[int][]SinkHit{},
		SourceToParam: map[int]*Node{},
		ParamToParam:  map[[2]int]ParamFlow{},
	}
}

func (s *FuncSummary) addSinkHit(param int, hit SinkHit) {
	for _, h := range s.ParamToSink[param] {
		if h.Pos == hit.Pos && h.Category == hit.Category {
			return
		}
	}
	s.ParamToSink[param] = append(s.ParamToSink[param], hit)
}

// signature is a cheap fingerprint used to detect fixpoint convergence.
func (s *FuncSummary) signature() string {
	var parts []string
	if s.SourceReturns != nil {
		parts = append(parts, "src")
	}
	for p, f := range s.ParamToReturn {
		parts = append(parts, fmt.Sprintf("r%d:%d", p, len(f.Sanitized)))
	}
	for p, hits := range s.ParamToSink {
		parts = append(parts, fmt.Sprintf("k%d:%d", p, len(hits)))
	}
	for p := range s.SourceToParam {
		parts = append(parts, fmt.Sprintf("o%d", p))
	}
	for k := range s.ParamToParam {
		parts = append(parts, fmt.Sprintf("pp%d-%d", k[0], k[1]))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (s *FuncSummary) empty() bool { return s.signature() == "" }

// fromState extracts return and out-parameter flows from a solved function state.
func (s *FuncSummary) fromState(st *funcState) {
	for root, n := range st.returns {
		if root == RootSource {
			s.SourceReturns = n
			continue
		}
		mergeFlow(s.ParamToReturn, root, ParamFlow{Sanitized: n.Sanitized, Steps: n.Trace()})
	}
	for i, p := range st.fn.Params {
		if !isPointerLike(p.Type()) {
			continue
		}
		sets := []taintSet{st.values[p]}
		for key, set := range st.fields {
			if key.base == ssa.Value(p) {
				sets = append(sets, set)
			}
		}
		for _, set := range sets {
			for root, n := range set {
				switch {
				case root == RootSource:
					if s.SourceToParam[i] == nil {
						s.SourceToParam[i] = n
					}
				case root != i:
					key := [2]int{root, i}
					if cur, ok := s.ParamToParam[key]; !ok || len(n.Sanitized) < len(cur.Sanitized) {
						s.ParamToParam[key] = ParamFlow{Sanitized: n.Sanitized, Steps: n.Trace()}
					}
				}
			}
		}
	}
}

func mergeFlow(m map[int]ParamFlow, p int, f ParamFlow) {
	if cur, ok := m[p]; ok && len(cur.Sanitized) <= len(f.Sanitized) {
		return
	}
	m[p] = f
}

// runInterprocedural computes summaries bottom-up over the call graph's SCCs
// and reports findings whose sources and sinks may live in different functions.
func (a *analysis) runInterprocedural() {
	done := map[*ssa.Function]bool{}
	for _, scc := range a.bundle.SCCs() {
		var members []*ssa.Function
		for _, fn := range scc {
			if fn.Blocks != nil && a.bundle.IsTarget(fn) {
				members = append(members, fn)
			}
		}
		if len(members) == 0 {
			continue
		}
		recursive := len(members) > 1 || a.selfRecursive(members[0])
		iterations := 1
		if recursive {
			iterations = 3
		}
		for iter := 0; iter < iterations; iter++ {
			changed := false
			for _, fn := range members {
				before := ""
				if old := a.summaries[fn]; old != nil {
					before = old.signature()
				}
				sum := a.analyze(fn)
				a.summaries[fn] = sum
				if sum.signature() != before {
					changed = true
				}
				done[fn] = true
			}
			if !changed {
				break
			}
		}
	}
	for _, fn := range a.bundle.TargetFunctions() {
		if !done[fn] {
			a.summaries[fn] = a.analyze(fn)
		}
	}
}

func (a *analysis) selfRecursive(fn *ssa.Function) bool {
	for _, callee := range a.bundle.Callees(fn) {
		if callee == fn {
			return true
		}
	}
	return false
}

// paramArgs aligns call-site values with the callee's SSA parameters.
func paramArgs(common *ssa.CallCommon) []ssa.Value {
	if common.IsInvoke() {
		return append([]ssa.Value{common.Value}, common.Args...)
	}
	return common.Args
}

// applySummaries models a call through the summaries of its resolved callees.
// It returns false when some callee has no summary so default propagation applies.
func (a *analysis) applySummaries(s *funcState, instr ssa.CallInstruction) bool {
	if !a.interproc || a.bundle == nil {
		return false
	}
	callees := a.bundle.CalleesAt(instr)
	if len(callees) == 0 {
		return false
	}
	values := paramArgs(instr.Common())
	pos := instr.Pos()
	result := instr.Value()
	complete := true
	for _, callee := range callees {
		sum := a.summaries[callee]
		if sum == nil || !a.bundle.IsTarget(callee) {
			if callee.Blocks == nil || !a.bundle.IsTarget(callee) {
				complete = false
			}
			continue
		}
		name := callee.Name()
		if recv := callee.Signature.Recv(); recv != nil && typeName(recv.Type()) != "" {
			name = typeName(recv.Type()) + "." + name
		}
		callStep := Step{Pos: pos, Kind: "call", Message: "passed to " + name}
		if sum.SourceReturns != nil && result != nil {
			s.addNode(result, sum.SourceReturns.derive(Step{Pos: pos, Kind: "return", Message: "untrusted value returned from " + name}))
		}
		for p, flow := range sum.ParamToReturn {
			if p >= len(values) || result == nil {
				continue
			}
			for _, n := range s.get(values[p]) {
				d := n.derive(append([]Step{callStep}, flow.Steps...)...)
				d.Sanitized = unionSanitized(n.Sanitized, flow.Sanitized)
				d.Steps = append(d.Steps, Step{Pos: pos, Kind: "return", Message: "returned from " + name})
				s.addNode(result, d)
			}
		}
		for p, n := range sum.SourceToParam {
			if p < len(values) {
				s.addNode(values[p], n.derive(Step{Pos: pos, Kind: "return", Message: "untrusted value written by " + name}))
			}
		}
		for key, flow := range sum.ParamToParam {
			if key[0] >= len(values) || key[1] >= len(values) {
				continue
			}
			for _, n := range s.get(values[key[0]]) {
				d := n.derive(append([]Step{callStep}, flow.Steps...)...)
				d.Sanitized = unionSanitized(n.Sanitized, flow.Sanitized)
				s.addNode(values[key[1]], d)
			}
		}
		for p, hits := range sum.ParamToSink {
			if p >= len(values) {
				continue
			}
			for _, n := range s.get(values[p]) {
				for _, hit := range hits {
					if n.sanitizedFor(hit.Category) {
						continue
					}
					d := n.derive(callStep)
					sink := d.derive(hit.Steps...)
					s.collect(n.Root, SinkHit{Category: hit.Category, Sink: hit.Sink, Pos: hit.Pos, Fn: hit.Fn, Steps: sink.Trace()}, sink)
				}
			}
		}
	}
	return complete
}

func unionSanitized(a, b map[string]bool) map[string]bool {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}
