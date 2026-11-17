package flow

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"golang.org/x/tools/go/ssa"
)

// Options configures a taint analysis run.
type Options struct {
	// Interprocedural enables function summaries propagated along the call graph.
	Interprocedural bool
}

// Engine runs taint analysis over the target functions of a GraphBundle.
type Engine struct {
	Bundle   *codessa.GraphBundle
	Registry *Registry
	Options  Options
}

// NewEngine creates a taint engine. A nil registry selects the built-in catalog.
func NewEngine(bundle *codessa.GraphBundle, reg *Registry, opts Options) *Engine {
	if reg == nil {
		reg = DefaultRegistry()
	}
	return &Engine{Bundle: bundle, Registry: reg, Options: opts}
}

// Finding is a source-to-sink flow.
type Finding struct {
	Category string
	Sink     *SinkSpec
	Pos      token.Pos
	Fn       *ssa.Function
	Node     *Node
}

// analysis holds the mutable state of one engine run.
type analysis struct {
	reg       *Registry
	bundle    *codessa.GraphBundle
	interproc bool
	summaries map[*ssa.Function]*FuncSummary
	findings  map[findingKey]*Finding
	order     []findingKey
}

type findingKey struct {
	category string
	pos      token.Pos
}

// Findings runs the analysis and returns raw findings in a deterministic order.
func (e *Engine) Findings() []*Finding {
	a := &analysis{
		reg:       e.Registry,
		bundle:    e.Bundle,
		interproc: e.Options.Interprocedural,
		summaries: map[*ssa.Function]*FuncSummary{},
		findings:  map[findingKey]*Finding{},
	}
	if e.Bundle == nil {
		return nil
	}
	if a.interproc {
		a.runInterprocedural()
	} else {
		for _, fn := range e.Bundle.TargetFunctions() {
			if fn.Parent() == nil {
				a.analyze(fn)
			}
		}
	}
	out := make([]*Finding, 0, len(a.order))
	for _, key := range a.order {
		out = append(out, a.findings[key])
	}
	fset := e.Bundle.Fset
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := fset.Position(out[i].Pos), fset.Position(out[j].Pos)
		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		if pi.Line != pj.Line {
			return pi.Line < pj.Line
		}
		if pi.Column != pj.Column {
			return pi.Column < pj.Column
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// Run executes the analysis and converts findings into issues.
func (e *Engine) Run() []result.Issue {
	findings := e.Findings()
	issues := make([]result.Issue, 0, len(findings))
	for _, f := range findings {
		issues = append(issues, e.toIssue(f))
	}
	return issues
}

func (e *Engine) toIssue(f *Finding) result.Issue {
	fset := e.Bundle.Fset
	info := e.Registry.Info(f.Category)
	pkgPath := ""
	if f.Fn != nil && f.Fn.Package() != nil {
		pkgPath = f.Fn.Package().Pkg.Path()
	}
	loc := result.NewLocationFromPos(fset.Position(f.Pos), "", pkgPath)
	if f.Fn != nil {
		loc.Function = functionName(f.Fn)
	}
	trace := f.Node.Trace()
	steps := make([]result.TraceStep, 0, len(trace))
	for _, st := range trace {
		if !st.Pos.IsValid() {
			continue
		}
		steps = append(steps, result.TraceStep{Location: result.NewLocationFromPos(fset.Position(st.Pos), "", ""), Message: st.Message, Kind: st.Kind})
	}
	source := ""
	for _, st := range trace {
		if st.Kind == "source" {
			source = st.Message
			break
		}
	}
	desc := info.Title
	if f.Sink != nil && f.Sink.Description != "" {
		desc = fmt.Sprintf("Untrusted data flows into %s", f.Sink.Description)
	}
	if source != "" {
		desc += " (" + source + ")"
	}
	return result.Issue{
		ID:          f.Category,
		Title:       info.Title,
		Description: desc,
		Severity:    info.Severity,
		Confidence:  f.Node.Confidence,
		CWE:         info.CWE,
		OWASP:       info.OWASP,
		Location:    loc,
		Category:    "security",
		Suggestion:  info.Suggestion,
		References:  info.References,
		Trace:       steps,
	}
}

func functionName(fn *ssa.Function) string {
	for fn.Parent() != nil {
		fn = fn.Parent()
	}
	if recv := fn.Signature.Recv(); recv != nil {
		if name := typeName(recv.Type()); name != "" {
			return name + "." + fn.Name()
		}
	}
	return fn.Name()
}

func (a *analysis) record(f *Finding) {
	if f.Node != nil && f.Node.Source.isLocal() && a.reg.Info(f.Category).TrustLocalSources {
		return
	}
	key := findingKey{f.Category, f.Pos}
	if _, ok := a.findings[key]; ok {
		return
	}
	a.findings[key] = f
	a.order = append(a.order, key)
}

// analyze runs the intraprocedural fixpoint on fn (and closures capturing
// tainted values) and checks sinks. With interprocedural analysis enabled,
// parameters are seeded with symbolic taint and a summary is returned.
func (a *analysis) analyze(fn *ssa.Function) *FuncSummary {
	sum := newSummary()
	collect := func(root int, hit SinkHit, node *Node) {
		if root == RootSource {
			a.record(&Finding{Category: hit.Category, Sink: hit.Sink, Pos: hit.Pos, Fn: hit.Fn, Node: node})
			return
		}
		sum.addSinkHit(root, hit)
	}
	st := newFuncState(a, fn)
	st.collect = collect
	for p, spec := range a.reg.paramSources(fn) {
		st.addNode(p, sourceNode(spec, p.Pos(), fmt.Sprintf("untrusted input received by %s as parameter %s", functionName(fn), p.Name())))
	}
	if a.interproc {
		for i, p := range fn.Params {
			if carries(p.Type()) {
				st.addNode(p, &Node{Root: i, Confidence: 1, Steps: []Step{{Pos: p.Pos(), Kind: "param", Message: fmt.Sprintf("parameter %s of %s", p.Name(), functionName(fn))}}})
			}
		}
	}
	a.solve(st, 0)
	if a.interproc {
		sum.fromState(st)
	}
	return sum
}

// solve runs the fixpoint, checks sinks and recursively analyzes closures with
// seeded free variables.
func (a *analysis) solve(st *funcState, depth int) {
	st.run()
	a.checkSinks(st)
	if depth > 8 {
		return
	}
	for anon, seeds := range st.closures {
		child := newFuncState(a, anon)
		child.collect = st.collect
		for i, set := range seeds {
			if i < len(anon.FreeVars) {
				child.valuesFor(anon.FreeVars[i]).merge(set)
			}
		}
		a.solve(child, depth+1)
	}
}

func (s *funcState) valuesFor(v ssa.Value) taintSet {
	set := s.values[v]
	if set == nil {
		set = taintSet{}
		s.values[v] = set
	}
	return set
}

// checkSinks reports tainted arguments reaching sinks and dangerous conversions.
func (a *analysis) checkSinks(st *funcState) {
	for _, block := range st.fn.Blocks {
		for _, instr := range block.Instrs {
			switch in := instr.(type) {
			case ssa.CallInstruction:
				a.checkCall(st, in)
			case *ssa.ChangeType:
				a.checkConversion(st, in, in.X)
			case *ssa.Convert:
				a.checkConversion(st, in, in.X)
			}
		}
	}
}

func (a *analysis) checkCall(st *funcState, instr ssa.CallInstruction) {
	common := instr.Common()
	t, ok := resolveTarget(common)
	if !ok {
		return
	}
	specs := a.reg.sinksFor(t)
	if len(specs) == 0 {
		return
	}
	_, args := EffectiveArgs(common)
	for _, spec := range specs {
		if spec.WriterArg >= 0 && (spec.WriterArg >= len(args) || !isResponseWriter(args[spec.WriterArg])) {
			continue
		}
		indexes := spec.CheckArgs
		if spec.AllArgs {
			indexes = make([]int, len(args))
			for i := range args {
				indexes[i] = i
			}
		}
		if spec.ShellArgs && len(indexes) > 1 && fixedProgram(args, indexes[0]) {
			indexes = indexes[:1]
		}
		for _, idx := range indexes {
			if idx < 0 || idx >= len(args) {
				continue
			}
			arg := args[idx]
			if constantSafe(spec.Category, arg) {
				continue
			}
			for _, n := range st.get(arg) {
				if n.sanitizedFor(spec.Category) {
					continue
				}
				sink := n.derive(Step{Pos: instr.Pos(), Kind: "sink", Message: fmt.Sprintf("reaches %s", describe(t))})
				st.collect(n.Root, SinkHit{Category: spec.Category, Sink: spec, Pos: instr.Pos(), Fn: st.fn, Steps: sink.Trace()}, sink)
			}
		}
	}
}

func (a *analysis) checkConversion(st *funcState, v ssa.Value, x ssa.Value) {
	spec := a.reg.conversionSink(v.Type())
	if spec == nil {
		return
	}
	for _, n := range st.get(x) {
		if n.sanitizedFor(spec.Category) {
			continue
		}
		pkg, name := typePkgName(v.Type())
		sink := n.derive(Step{Pos: v.Pos(), Kind: "sink", Message: fmt.Sprintf("converted to trusted %s.%s", pkg, name)})
		st.collect(n.Root, SinkHit{Category: spec.Category, Sink: spec, Pos: v.Pos(), Fn: st.fn, Steps: sink.Trace()}, sink)
	}
}

// isResponseWriter reports whether v (possibly wrapped in an interface) is an
// HTTP response writer, i.e. exposes Header, Write and WriteHeader.
func isResponseWriter(v ssa.Value) bool {
	for {
		switch x := v.(type) {
		case *ssa.MakeInterface:
			v = x.X
			continue
		case *ssa.ChangeInterface:
			v = x.X
			continue
		}
		break
	}
	t := v.Type()
	if pkg, name := typePkgName(t); pkg == "net/http" && name == "ResponseWriter" {
		return true
	}
	for _, m := range []string{"Header", "WriteHeader", "Write"} {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, m)
		if _, ok := obj.(*types.Func); !ok {
			return false
		}
	}
	return true
}

var fixedHostPrefix = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#@]+[/?#]`)

// constantSafe reports whether a constant prefix of v makes the sink safe:
// URLs whose scheme and host are fixed cannot be redirected to other hosts,
// and redirects to local absolute paths stay on the same origin.
func constantSafe(category string, v ssa.Value) bool {
	if category != "ssrf" && category != "open-redirect" {
		return false
	}
	prefix := constPrefix(v, 0)
	if fixedHostPrefix.MatchString(prefix) {
		return true
	}
	return category == "open-redirect" && strings.HasPrefix(prefix, "/") && len(prefix) > 1 && prefix[1] != '/' && prefix[1] != '\\'
}

// constPrefix returns the statically known leading text of a string value.
func constPrefix(v ssa.Value, depth int) string {
	if depth > 8 {
		return ""
	}
	switch x := v.(type) {
	case *ssa.Const:
		if x.Value != nil && x.Value.Kind() == constant.String {
			return constant.StringVal(x.Value)
		}
	case *ssa.BinOp:
		if x.Op == token.ADD {
			left := constPrefix(x.X, depth+1)
			if c, ok := x.X.(*ssa.Const); ok && c.Value != nil {
				return left + constPrefix(x.Y, depth+1)
			}
			return left
		}
	case *ssa.MakeInterface:
		return constPrefix(x.X, depth+1)
	case *ssa.Convert:
		return constPrefix(x.X, depth+1)
	case *ssa.ChangeType:
		return constPrefix(x.X, depth+1)
	case *ssa.Call:
		if fn := x.Call.StaticCallee(); fn != nil && fn.Pkg != nil && fn.Pkg.Pkg.Path() == "fmt" && fn.Name() == "Sprintf" && len(x.Call.Args) > 0 {
			format := constPrefix(x.Call.Args[0], depth+1)
			if i := strings.IndexByte(format, '%'); i >= 0 {
				return format[:i]
			}
			return format
		}
	case *ssa.Phi:
		var common string
		for i, edge := range x.Edges {
			p := constPrefix(edge, depth+1)
			if i == 0 {
				common = p
				continue
			}
			for !strings.HasPrefix(p, common) {
				common = common[:len(common)-1]
			}
		}
		return common
	}
	return ""
}

// shellPrograms are interpreters whose arguments are executed as commands.
var shellPrograms = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "cmd": true, "cmd.exe": true,
	"powershell": true, "powershell.exe": true, "pwsh": true}

// fixedProgram reports whether args[i] names a constant program other than a shell.
func fixedProgram(args []ssa.Value, i int) bool {
	if i >= len(args) {
		return false
	}
	c, ok := args[i].(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.String {
		return false
	}
	return !shellPrograms[strings.ToLower(path.Base(constant.StringVal(c.Value)))]
}
