// Package flow implements SSA-based taint tracking from untrusted sources to
// security-sensitive sinks, with sanitizers and interprocedural summaries.
package flow

import (
	"go/types"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"golang.org/x/tools/go/ssa"
)

// SourceKind describes how a source introduces untrusted data.
type SourceKind int

const (
	// SourceCall marks the results of a call as tainted.
	SourceCall SourceKind = iota
	// SourceField marks reads of a struct field as tainted.
	SourceField
	// SourceGlobal marks loads of a package-level variable as tainted.
	SourceGlobal
	// SourceOutArg marks pointer arguments written by a call as tainted.
	SourceOutArg
	// SourceParam marks function parameters of a given type as tainted, such as
	// the request of an RPC handler.
	SourceParam
)

// SourceSpec identifies an untrusted input.
type SourceSpec struct {
	Package  string // Import path of the declaring package.
	Receiver string // Receiver type name without pointer; empty for functions, fields use the struct name.
	Function string // Function, method, field or variable name.
	Kind     SourceKind
	OutArgs  []int // For SourceOutArg: effective argument indexes receiving data.
	Tags     []string
	// Confidence of findings originating from this source (0 means 1.0).
	Confidence  float64
	Description string
}

// SinkSpec identifies a security-sensitive call.
type SinkSpec struct {
	Package   string
	Receiver  string
	Function  string
	CheckArgs []int // Effective argument indexes (receiver excluded).
	AllArgs   bool  // Check every effective argument.
	// ShellArgs limits the check to the first index of CheckArgs (the program
	// name) when that argument is a constant other than a shell: arguments
	// passed to a fixed program cannot inject commands.
	ShellArgs bool
	// WriterArg, when >= 0, requires that effective argument to be an http.ResponseWriter.
	WriterArg int
	// Conversion marks a type conversion sink (Function is the target type name).
	Conversion  bool
	Category    string
	Description string
}

// SanitizerSpec identifies a function whose result is safe for the given categories.
type SanitizerSpec struct {
	Package    string
	Receiver   string
	Function   string
	Categories []string // "*" clears every category.
}

// CategoryInfo describes the finding produced for a sink category.
type CategoryInfo struct {
	Title      string
	CWE        string
	OWASP      string
	Severity   result.Severity
	Suggestion string
	References []string
	// TrustLocalSources ignores flows from sources controlled by whoever runs
	// the program (environment variables, command-line arguments, stdin).
	TrustLocalSources bool
}

// localSourceTags are the source tags of operator-controlled input.
var localSourceTags = map[string]bool{"env": true, "cli": true}

// isLocal reports whether s is operator-controlled input.
func (s *SourceSpec) isLocal() bool {
	if s == nil {
		return false
	}
	for _, tag := range s.Tags {
		if localSourceTags[tag] {
			return true
		}
	}
	return false
}

// Registry holds sources, sinks and sanitizers.
type Registry struct {
	Sources    []SourceSpec
	Sinks      []SinkSpec
	Sanitizers []SanitizerSpec
	Categories map[string]CategoryInfo
}

// target identifies the callee of a call site.
type target struct {
	pkg, recv, name string
}

func (t target) matches(pkg, recv, name string) bool {
	return t.pkg == pkg && t.recv == recv && t.name == name
}

// resolveTarget determines the declared identity of a call's callee, using the
// declared receiver for promoted methods and the interface type for invocations.
func resolveTarget(common *ssa.CallCommon) (target, bool) {
	if common.IsInvoke() {
		m := common.Method
		if m.Pkg() == nil {
			return target{}, false
		}
		return target{pkg: m.Pkg().Path(), recv: typeName(common.Value.Type()), name: m.Name()}, true
	}
	fn := common.StaticCallee()
	if fn == nil {
		return target{}, false
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil {
		return target{}, false
	}
	t := target{pkg: obj.Pkg().Path(), name: obj.Name()}
	if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
		t.recv = typeName(sig.Recv().Type())
	}
	return t, true
}

// typeName returns the name of a (possibly pointer to) named type.
func typeName(t types.Type) string {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	switch n := types.Unalias(t).(type) {
	case *types.Named:
		return n.Obj().Name()
	}
	return ""
}

// typePkgName returns the package path and name of a (possibly pointer to) named type.
func typePkgName(t types.Type) (string, string) {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Path(), n.Obj().Name()
	}
	return "", ""
}

func (r *Registry) sourcesFor(t target, kind SourceKind) []*SourceSpec {
	var out []*SourceSpec
	for i := range r.Sources {
		s := &r.Sources[i]
		if s.Kind == kind && t.matches(s.Package, s.Receiver, s.Function) {
			out = append(out, s)
		}
	}
	return out
}

func (r *Registry) sinksFor(t target) []*SinkSpec {
	var out []*SinkSpec
	for i := range r.Sinks {
		s := &r.Sinks[i]
		if !s.Conversion && t.matches(s.Package, s.Receiver, s.Function) {
			out = append(out, s)
		}
	}
	return out
}

func (r *Registry) conversionSink(t types.Type) *SinkSpec {
	pkg, name := typePkgName(t)
	if pkg == "" {
		return nil
	}
	for i := range r.Sinks {
		s := &r.Sinks[i]
		if s.Conversion && s.Package == pkg && s.Function == name {
			return s
		}
	}
	return nil
}

func (r *Registry) sanitizerFor(t target) *SanitizerSpec {
	for i := range r.Sanitizers {
		s := &r.Sanitizers[i]
		if t.matches(s.Package, s.Receiver, s.Function) {
			return s
		}
	}
	return nil
}

// Info returns the category metadata, falling back to a generic description.
func (r *Registry) Info(category string) CategoryInfo {
	if info, ok := r.Categories[category]; ok {
		return info
	}
	return CategoryInfo{Title: "Untrusted data reaches sensitive sink", Severity: result.SeverityHigh, Suggestion: "Validate or sanitize untrusted input before using it in this call."}
}

// EffectiveArgs re-exports the receiver-aware argument normalization.
func EffectiveArgs(common *ssa.CallCommon) (ssa.Value, []ssa.Value) {
	return codessa.EffectiveArgs(common)
}
