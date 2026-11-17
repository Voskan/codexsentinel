// Package critsec finds blocking calls inside critical sections: network
// requests and sleeps while a SQL transaction is open or a mutex is held.
// Such calls hold database row locks, pool connections or the mutex for as
// long as a remote service takes to answer.
package critsec

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"golang.org/x/tools/go/ssa"
)

// Rule IDs reported by Analyze.
const (
	TxNetworkIO    = "tx-network-io"
	LockBlockingIO = "lock-blocking-io"
)

// maxDepth bounds the call chain followed from a critical section.
const maxDepth = 8

// Analyze reports blocking calls made directly or through project functions
// while a transaction is open or a mutex is held. Only functions in the files
// selected for analysis are reported.
func Analyze(ws *workspace.Workspace, bundle *codessa.GraphBundle, enabled func(id string) bool) []result.Issue {
	if ws == nil || bundle == nil {
		return nil
	}
	a := &analyzer{bundle: bundle, witnesses: map[*ssa.Function]*witness{}, visiting: map[*ssa.Function]bool{}, selected: selectedFiles(ws)}
	for _, fn := range bundle.TargetFunctions() {
		if !a.selected[a.file(fn.Pos())] {
			continue
		}
		for _, r := range regions(fn) {
			if enabled != nil && !enabled(r.rule) {
				continue
			}
			a.checkRegion(r)
		}
	}
	sort.SliceStable(a.issues, func(i, j int) bool {
		x, y := a.issues[i].Location, a.issues[j].Location
		if x.File != y.File {
			return x.File < y.File
		}
		return x.Line < y.Line
	})
	return a.issues
}

func selectedFiles(ws *workspace.Workspace) map[string]bool {
	out := map[string]bool{}
	for _, pkg := range ws.Packages {
		for _, f := range ws.Files(pkg) {
			out[ws.Fset.Position(f.Pos()).Filename] = true
		}
	}
	return out
}

type analyzer struct {
	bundle    *codessa.GraphBundle
	witnesses map[*ssa.Function]*witness
	visiting  map[*ssa.Function]bool
	selected  map[string]bool
	issues    []result.Issue
	reported  map[token.Pos]bool
}

func (a *analyzer) file(pos token.Pos) string { return a.bundle.Fset.Position(pos).Filename }

// witness is a call chain from a function to a blocking call.
type witness struct {
	site  ssa.CallInstruction // call in the function
	name  string              // what is called at site
	next  *witness            // continuation in the callee, nil for a blocking call
	kind  string              // description of the blocking operation
	depth int
}

// blocking returns the shortest known chain from fn to a blocking call through
// project functions, or nil.
func (a *analyzer) blocking(fn *ssa.Function) *witness {
	if w, ok := a.witnesses[fn]; ok {
		return w
	}
	if a.visiting[fn] || fn.Blocks == nil || !a.bundle.IsTarget(fn) {
		return nil
	}
	a.visiting[fn] = true
	var best *witness
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			site, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if w := a.callWitness(site); w != nil && (best == nil || w.depth < best.depth) {
				best = w
			}
		}
	}
	delete(a.visiting, fn)
	a.witnesses[fn] = best
	return best
}

// callWitness returns the chain from a call site to a blocking call: the site
// itself when it calls a blocking API, or the site followed by a callee chain.
func (a *analyzer) callWitness(site ssa.CallInstruction) *witness {
	if _, isGo := site.(*ssa.Go); isGo {
		return nil // runs concurrently; does not block the caller
	}
	if kind, name := blockingCall(site.Common()); kind != "" {
		return &witness{site: site, name: name, kind: kind, depth: 1}
	}
	var best *witness
	for _, callee := range a.bundle.CalleesAt(site) {
		next := a.blocking(callee)
		if next == nil || next.depth >= maxDepth {
			continue
		}
		if best == nil || next.depth+1 < best.depth {
			best = &witness{site: site, name: funcName(callee), next: next, kind: next.kind, depth: next.depth + 1}
		}
	}
	return best
}

// chain renders a witness as "A -> B -> (*net/http.Client).Do".
func (w *witness) chain() string {
	var parts []string
	for cur := w; cur != nil; cur = cur.next {
		parts = append(parts, cur.name)
	}
	return strings.Join(parts, " -> ")
}

func (a *analyzer) checkRegion(r region) {
	if a.reported == nil {
		a.reported = map[token.Pos]bool{}
	}
	for _, site := range r.calls {
		w := a.callWitness(site)
		if w == nil || a.reported[site.Pos()] {
			continue
		}
		a.reported[site.Pos()] = true
		a.issues = append(a.issues, a.issue(r, w))
	}
}

func (a *analyzer) issue(r region, w *witness) result.Issue {
	pos := a.bundle.Fset.Position(w.site.Pos())
	start := a.bundle.Fset.Position(r.start)
	trace := []result.TraceStep{{Location: location(start, r.fn), Kind: "source", Message: r.what + " starts here"}}
	for cur := w; cur != nil; cur = cur.next {
		kind := "call"
		msg := "calls " + cur.name
		if cur.next == nil {
			kind, msg = "sink", cur.kind+": "+cur.name
		}
		trace = append(trace, result.TraceStep{Location: location(a.bundle.Fset.Position(cur.site.Pos()), cur.site.Parent()), Kind: kind, Message: msg})
	}
	issue := result.Issue{
		ID: r.rule, Category: "reliability", Location: location(pos, r.fn), Trace: trace, Confidence: 0.8,
	}
	desc := fmt.Sprintf("%s (%s) runs while %s opened at line %d is held", w.kind, w.chain(), r.what, start.Line)
	switch r.rule {
	case TxNetworkIO:
		issue.Title, issue.Severity, issue.CWE, issue.OWASP = "Blocking Call Inside a Database Transaction", result.SeverityHigh, "CWE-400", "A06:2025"
		issue.Description = desc + "; the transaction keeps its connection and row locks until the remote call returns."
		issue.Suggestion = "Call remote services before opening the transaction or after committing it; use an outbox table for side effects that must follow the commit."
	default:
		issue.Title, issue.Severity, issue.CWE, issue.OWASP = "Blocking Call While Holding a Mutex", result.SeverityMedium, "CWE-833", "A06:2025"
		issue.Description = desc + "; every goroutine waiting for the lock is stalled until the call returns."
		issue.Suggestion = "Copy the data you need under the lock, unlock, then make the call; or use singleflight to deduplicate concurrent fetches."
	}
	return issue
}

func location(pos token.Position, fn *ssa.Function) result.Location {
	loc := result.NewLocationFromPos(pos, "", "")
	if fn != nil {
		loc.Function = funcName(fn)
		if fn.Pkg != nil {
			loc.PackagePath = fn.Pkg.Pkg.Path()
		}
	}
	return loc
}

// funcName returns a short name such as "OrderService.PlaceOrder".
func funcName(fn *ssa.Function) string {
	if fn.Parent() != nil {
		return funcName(fn.Parent()) + ".func"
	}
	if recv := fn.Signature.Recv(); recv != nil {
		t := recv.Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := t.(*types.Named); ok {
			return n.Obj().Name() + "." + fn.Name()
		}
	}
	return fn.Name()
}

// blockingCall classifies a call to a blocking API. It returns the kind of
// operation and the callee name, or "" when the call does not block.
func blockingCall(common *ssa.CallCommon) (kind, name string) {
	pkg, recv, fn := callee(common)
	if pkg == "" {
		return "", ""
	}
	name = pkg + "." + fn
	if recv != "" {
		name = fmt.Sprintf("(%s.%s).%s", pkg, recv, fn)
	}
	switch {
	case pkg == "net/http" && recv == "" && in(fn, "Get", "Post", "Head", "PostForm"),
		pkg == "net/http" && recv == "Client" && in(fn, "Do", "Get", "Post", "Head", "PostForm"),
		pkg == "net/http" && (recv == "Transport" || recv == "RoundTripper") && fn == "RoundTrip":
		return "HTTP request", name
	case pkg == "google.golang.org/grpc" && (recv == "ClientConn" || recv == "ClientConnInterface") && in(fn, "Invoke", "NewStream"),
		pkg == "google.golang.org/grpc" && recv == "" && fn == "Invoke":
		return "gRPC call", name
	case pkg == "net" && recv == "" && strings.HasPrefix(fn, "Dial"),
		pkg == "net" && recv == "Dialer" && in(fn, "Dial", "DialContext"):
		return "network connection", name
	case pkg == "net/smtp" && recv == "" && in(fn, "SendMail", "Dial"):
		return "SMTP request", name
	case pkg == "time" && recv == "" && fn == "Sleep":
		return "sleep", name
	}
	return "", ""
}

// callee returns the declaring package, receiver type name and name of the
// function called, for static calls and interface invocations.
func callee(common *ssa.CallCommon) (pkg, recv, name string) {
	if common.IsInvoke() {
		m := common.Method
		if m.Pkg() == nil {
			return "", "", ""
		}
		return m.Pkg().Path(), namedName(common.Value.Type()), m.Name()
	}
	fn := common.StaticCallee()
	if fn == nil {
		return "", "", ""
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Pkg() == nil {
		return "", "", ""
	}
	if sig := obj.Type().(*types.Signature); sig.Recv() != nil {
		recv = namedName(sig.Recv().Type())
	}
	return obj.Pkg().Path(), recv, obj.Name()
}

func namedName(t types.Type) string {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

func in(s string, list ...string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}
