package flow

import (
	"fmt"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// RootSource is the root key of taint that originates from a real source.
// Non-negative roots denote symbolic taint flowing from a function parameter.
const RootSource = -1

// Step is one element of a taint trace.
type Step struct {
	Pos     token.Pos
	Kind    string // "source" | "param" | "propagation" | "call" | "return" | "sink"
	Message string
}

// Node is a link in a taint propagation chain. Chains are shared and immutable.
type Node struct {
	Root       int
	Source     *SourceSpec
	Confidence float64
	Steps      []Step
	Prev       *Node
	Sanitized  map[string]bool
}

// Trace returns the full ordered list of steps leading to this node.
func (n *Node) Trace() []Step {
	var chain []*Node
	for cur := n; cur != nil; cur = cur.Prev {
		chain = append(chain, cur)
	}
	var steps []Step
	for i := len(chain) - 1; i >= 0; i-- {
		steps = append(steps, chain[i].Steps...)
	}
	return steps
}

// derive creates a successor node carrying root, source and sanitization state.
func (n *Node) derive(steps ...Step) *Node {
	return &Node{Root: n.Root, Source: n.Source, Confidence: n.Confidence, Steps: steps, Prev: n, Sanitized: n.Sanitized}
}

func (n *Node) sanitizedFor(category string) bool {
	return n.Sanitized[category]
}

func (n *Node) withSanitized(categories []string) *Node {
	merged := make(map[string]bool, len(n.Sanitized)+len(categories))
	for k := range n.Sanitized {
		merged[k] = true
	}
	for _, c := range categories {
		merged[c] = true
	}
	d := n.derive()
	d.Sanitized = merged
	return d
}

// better reports whether candidate should replace current: fewer sanitized categories wins.
func better(candidate, current *Node) bool {
	if current == nil {
		return true
	}
	if len(candidate.Sanitized) >= len(current.Sanitized) {
		return false
	}
	for k := range candidate.Sanitized {
		if !current.Sanitized[k] {
			return false
		}
	}
	return true
}

// taintSet maps a root key to the least-sanitized node reaching a value.
type taintSet map[int]*Node

type fieldKey struct {
	base ssa.Value
	path string
}

// funcState holds the taint facts of one function analysis.
type funcState struct {
	eng    *analysis
	fn     *ssa.Function
	values map[ssa.Value]taintSet
	fields map[fieldKey]taintSet
	// changed is set when a fixpoint iteration adds information.
	changed bool
	// closures seeds free variables of anonymous functions created in fn.
	closures map[*ssa.Function]map[int]taintSet
	// returns collects taint reaching return statements.
	returns taintSet
	// collect receives sink hits; source-rooted hits become findings.
	collect func(root int, hit SinkHit, node *Node)
}

func newFuncState(a *analysis, fn *ssa.Function) *funcState {
	return &funcState{
		eng:      a,
		fn:       fn,
		values:   map[ssa.Value]taintSet{},
		fields:   map[fieldKey]taintSet{},
		closures: map[*ssa.Function]map[int]taintSet{},
		returns:  taintSet{},
	}
}

// carries reports whether values of type t can hold attacker-controlled text.
// Numbers, booleans, errors and functions cannot carry injection payloads.
func carries(t types.Type) bool {
	switch u := types.Unalias(t).(type) {
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if carries(u.At(i).Type()) {
				return true
			}
		}
		return false
	case *types.Named:
		if u.Obj().Pkg() == nil && u.Obj().Name() == "error" {
			return false
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0 || u.Kind() == types.UnsafePointer || u.Kind() == types.Invalid
	case *types.Pointer:
		return carries(u.Elem())
	case *types.Slice:
		return carriesElem(u.Elem())
	case *types.Array:
		return carriesElem(u.Elem())
	case *types.Chan:
		return carries(u.Elem())
	case *types.Signature:
		return false
	}
	return true
}

func carriesElem(elem types.Type) bool {
	if b, ok := elem.Underlying().(*types.Basic); ok && b.Info()&types.IsNumeric != 0 {
		return b.Kind() == types.Uint8 || b.Kind() == types.Int32
	}
	return carries(elem)
}

func (s *funcState) get(v ssa.Value) taintSet {
	if v == nil {
		return nil
	}
	return s.values[v]
}

func (s *funcState) addNode(v ssa.Value, n *Node) {
	if v == nil || n == nil || !carries(v.Type()) {
		return
	}
	set := s.values[v]
	if set == nil {
		set = taintSet{}
		s.values[v] = set
	}
	if better(n, set[n.Root]) {
		set[n.Root] = n
		s.changed = true
	}
}

// flow propagates every node of from into to, recording an optional step.
func (s *funcState) flow(to ssa.Value, from ssa.Value, step *Step) {
	set := s.get(from)
	if len(set) == 0 || to == nil {
		return
	}
	for _, n := range set {
		cur := s.values[to][n.Root]
		if cur != nil && !better(n, cur) {
			continue
		}
		if step != nil {
			s.addNode(to, n.derive(*step))
		} else {
			s.addNode(to, n)
		}
	}
}

// merge adds the nodes of set that improve on dst and reports whether dst changed.
func (dst taintSet) merge(set taintSet) bool {
	changed := false
	for root, n := range set {
		if better(n, dst[root]) {
			dst[root] = n
			changed = true
		}
	}
	return changed
}

func (s *funcState) addField(key fieldKey, set taintSet) {
	if len(set) == 0 {
		return
	}
	dst := s.fields[key]
	if dst == nil {
		dst = taintSet{}
		s.fields[key] = dst
	}
	if dst.merge(set) {
		s.changed = true
	}
}

// fieldPath canonicalizes a chain of FieldAddr instructions to its base and path.
func fieldPath(v ssa.Value) (ssa.Value, string) {
	var parts []string
	for {
		fa, ok := v.(*ssa.FieldAddr)
		if !ok {
			break
		}
		parts = append(parts, strconv.Itoa(fa.Field))
		v = fa.X
	}
	if len(parts) == 0 {
		return v, ""
	}
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteByte('.')
		b.WriteString(parts[i])
	}
	return v, b.String()
}

// run iterates the transfer functions over fn until no new facts are produced.
func (s *funcState) run() {
	if s.fn.Blocks == nil {
		return
	}
	for iter := 0; iter < 50; iter++ {
		s.changed = false
		for _, block := range s.fn.Blocks {
			for _, instr := range block.Instrs {
				s.transfer(instr)
			}
		}
		if !s.changed {
			break
		}
	}
}

func newStep(pos token.Pos, kind, format string, args ...any) *Step {
	return &Step{Pos: pos, Kind: kind, Message: fmt.Sprintf(format, args...)}
}

func (s *funcState) transfer(instr ssa.Instruction) {
	if v, from := passThrough(instr); from != nil {
		s.flow(v, from, nil)
		return
	}
	switch in := instr.(type) {
	case *ssa.BinOp:
		s.flow(in, in.X, nil)
		s.flow(in, in.Y, nil)
	case *ssa.UnOp:
		if g, ok := in.X.(*ssa.Global); ok {
			s.globalSource(in, g)
		}
		if in.Op == token.MUL || in.Op == token.ARROW {
			s.flow(in, in.X, nil)
		}
	case *ssa.Phi:
		for _, edge := range in.Edges {
			s.flow(in, edge, nil)
		}
	case *ssa.FieldAddr:
		s.fieldSource(in, in.X, in.Field)
		s.flow(in, in.X, nil)
		base, path := fieldPath(in)
		for prefix := path; prefix != ""; prefix = prefix[:strings.LastIndexByte(prefix, '.')] {
			for _, n := range s.fields[fieldKey{base, prefix}] {
				s.addNode(in, n)
			}
		}
	case *ssa.Field:
		s.fieldSource(in, in.X, in.Field)
		s.flow(in, in.X, nil)
	case *ssa.Store:
		s.store(in.Addr, in.Val, in.Pos())
	case *ssa.MapUpdate:
		s.flow(in.Map, in.Value, nil)
		s.flow(in.Map, in.Key, nil)
	case *ssa.Send:
		s.flow(in.Chan, in.X, nil)
	case *ssa.MakeClosure:
		s.closure(in)
	case *ssa.Return:
		for _, r := range in.Results {
			if s.returns.merge(s.get(r)) {
				s.changed = true
			}
		}
	case ssa.CallInstruction:
		s.call(in)
	}
}

// passThrough returns the value defined by instructions that propagate the
// taint of a single operand unchanged (conversions, extraction, indexing,
// slicing and iteration), together with that operand.
func passThrough(instr ssa.Instruction) (ssa.Value, ssa.Value) {
	switch in := instr.(type) {
	case *ssa.Convert:
		return in, in.X
	case *ssa.ChangeType:
		return in, in.X
	case *ssa.ChangeInterface:
		return in, in.X
	case *ssa.MakeInterface:
		return in, in.X
	case *ssa.TypeAssert:
		return in, in.X
	case *ssa.SliceToArrayPointer:
		return in, in.X
	case *ssa.MultiConvert:
		return in, in.X
	case *ssa.Extract:
		return in, in.Tuple
	case *ssa.IndexAddr:
		return in, in.X
	case *ssa.Index:
		return in, in.X
	case *ssa.Lookup:
		return in, in.X
	case *ssa.Slice:
		return in, in.X
	case *ssa.Range:
		return in, in.X
	case *ssa.Next:
		return in, in.Iter
	}
	return nil, nil
}

func (s *funcState) store(addr, val ssa.Value, pos token.Pos) {
	set := s.get(val)
	if len(set) == 0 {
		return
	}
	switch a := addr.(type) {
	case *ssa.FieldAddr:
		base, path := fieldPath(a)
		s.addField(fieldKey{base, path}, set)
		s.flow(a, val, nil)
	case *ssa.IndexAddr:
		s.flow(a.X, val, nil)
		s.flow(a, val, nil)
	default:
		s.flow(addr, val, nil)
	}
}

func (s *funcState) closure(mc *ssa.MakeClosure) {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok {
		return
	}
	for i, binding := range mc.Bindings {
		set := s.get(binding)
		if len(set) == 0 || i >= len(fn.FreeVars) {
			continue
		}
		seeds := s.closures[fn]
		if seeds == nil {
			seeds = map[int]taintSet{}
			s.closures[fn] = seeds
		}
		if seeds[i] == nil {
			seeds[i] = taintSet{}
		}
		if seeds[i].merge(set) {
			s.changed = true
		}
	}
}

func (s *funcState) globalSource(load *ssa.UnOp, g *ssa.Global) {
	if g.Pkg == nil {
		return
	}
	t := target{pkg: g.Pkg.Pkg.Path(), name: g.Name()}
	for _, spec := range s.eng.reg.sourcesFor(t, SourceGlobal) {
		s.addNode(load, sourceNode(spec, load.Pos(), fmt.Sprintf("untrusted input read from %s.%s", t.pkg, t.name)))
	}
}

func (s *funcState) fieldSource(v ssa.Value, x ssa.Value, field int) {
	t := x.Type()
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || field >= st.NumFields() {
		return
	}
	pkg, name := typePkgName(t)
	if pkg == "" {
		return
	}
	fname := st.Field(field).Name()
	for _, spec := range s.eng.reg.sourcesFor(target{pkg: pkg, recv: name, name: fname}, SourceField) {
		s.addNode(v, sourceNode(spec, v.Pos(), fmt.Sprintf("untrusted input read from %s.%s", name, fname)))
	}
}

func sourceNode(spec *SourceSpec, pos token.Pos, msg string) *Node {
	conf := spec.Confidence
	if conf == 0 {
		conf = 1
	}
	return &Node{Root: RootSource, Source: spec, Confidence: conf, Steps: []Step{{Pos: pos, Kind: "source", Message: msg}}}
}

// outParamMethods name library calls that write data from their inputs into
// pointer arguments or their receiver.
var outParamMethods = map[string]bool{
	"Read": true, "ReadFull": true, "ReadAtLeast": true, "Copy": true, "CopyN": true, "CopyBuffer": true,
	"Unmarshal": true, "Decode": true,
}

var receiverWriters = []string{"Write", "Set", "Add", "Append", "Store", "Push", "Put", "Insert", "Print"}

func describe(t target) string {
	switch {
	case t.recv != "":
		return fmt.Sprintf("(%s.%s).%s", t.pkg, t.recv, t.name)
	case t.pkg != "":
		return t.pkg + "." + t.name
	}
	return t.name
}

func (s *funcState) call(instr ssa.CallInstruction) {
	common := instr.Common()
	result := instr.Value()
	if b, ok := common.Value.(*ssa.Builtin); ok {
		s.builtin(b, common, result)
		return
	}
	recv, args := EffectiveArgs(common)
	t, known := resolveTarget(common)
	pos := instr.Pos()
	if known {
		name := describe(t)
		for _, spec := range s.eng.reg.sourcesFor(t, SourceCall) {
			s.addNode(result, sourceNode(spec, pos, "untrusted input returned by "+name))
		}
		for _, spec := range s.eng.reg.sourcesFor(t, SourceOutArg) {
			for _, idx := range spec.OutArgs {
				if idx < len(args) {
					s.addNode(args[idx], sourceNode(spec, pos, "untrusted input decoded by "+name))
				}
			}
		}
		if san := s.eng.reg.sanitizerFor(t); san != nil {
			s.sanitize(result, recv, args, san, pos, name)
			return
		}
	}
	if s.eng.applySummaries(s, instr) {
		return
	}
	s.defaultPropagation(instr, t, known, recv, args)
}

func (s *funcState) sanitize(result, recv ssa.Value, args []ssa.Value, san *SanitizerSpec, pos token.Pos, name string) {
	for _, c := range san.Categories {
		if c == "*" {
			return
		}
	}
	inputs := append([]ssa.Value{recv}, args...)
	for _, in := range inputs {
		for _, n := range s.get(in) {
			d := n.withSanitized(san.Categories)
			d.Steps = []Step{{Pos: pos, Kind: "propagation", Message: "sanitized by " + name + " for " + strings.Join(san.Categories, ", ")}}
			s.addNode(result, d)
		}
	}
}

func (s *funcState) builtin(b *ssa.Builtin, common *ssa.CallCommon, result ssa.Value) {
	switch b.Name() {
	case "append", "min", "max":
		for _, arg := range common.Args {
			s.flow(result, arg, nil)
		}
	case "copy":
		if len(common.Args) == 2 {
			s.flow(common.Args[0], common.Args[1], nil)
		}
	}
}

// defaultPropagation models calls without a specification: results derive from
// the receiver and arguments, and well-known writer or decoder methods taint
// their receiver or pointer arguments.
func (s *funcState) defaultPropagation(instr ssa.CallInstruction, t target, known bool, recv ssa.Value, args []ssa.Value) {
	inputs := args
	if recv != nil {
		inputs = append([]ssa.Value{recv}, args...)
	} else if !instr.Common().IsInvoke() && instr.Common().StaticCallee() == nil {
		// Dynamic call through a function value.
		inputs = append([]ssa.Value{instr.Common().Value}, args...)
	}
	pos := instr.Pos()
	result := instr.Value()
	label := "call"
	if known {
		label = describe(t)
	}
	if result != nil && carries(result.Type()) {
		for _, in := range inputs {
			if len(s.get(in)) > 0 {
				s.flow(result, in, newStep(pos, "propagation", "flows through %s", label))
			}
		}
	}
	if !known {
		return
	}
	if recv != nil && len(args) > 0 {
		for _, prefix := range receiverWriters {
			if strings.HasPrefix(t.name, prefix) {
				for _, a := range args {
					s.flow(recv, a, newStep(pos, "propagation", "written into receiver by %s", label))
				}
				break
			}
		}
	}
	if outParamMethods[t.name] {
		var tainted []ssa.Value
		for _, in := range inputs {
			if len(s.get(in)) > 0 {
				tainted = append(tainted, in)
			}
		}
		for _, a := range args {
			if !isPointerLike(a.Type()) {
				continue
			}
			for _, src := range tainted {
				if src != a {
					s.flow(a, src, newStep(pos, "propagation", "decoded into argument by %s", label))
				}
			}
		}
	}
}

func isPointerLike(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map:
		return true
	case *types.Interface:
		return true
	default:
		_ = u
		return false
	}
}
