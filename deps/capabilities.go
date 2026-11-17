package deps

import (
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/v2/analyzer/ssa"
	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// Capability is a class of privileged operation a dependency performs.
type Capability string

const (
	CapExec    Capability = "CAP_EXEC"     // Starts processes
	CapNetwork Capability = "CAP_NETWORK"  // Opens connections or listeners
	CapFSWrite Capability = "CAP_FS_WRITE" // Creates, modifies or removes files
	CapFSRead  Capability = "CAP_FS_READ"  // Reads files or directories
	CapEnv     Capability = "CAP_ENV"      // Reads environment variables
	CapUnsafe  Capability = "CAP_UNSAFE"   // Uses package unsafe
	CapCgo     Capability = "CAP_CGO"      // Calls C code
	CapPlugin  Capability = "CAP_PLUGIN"   // Loads Go plugins
	CapReflect Capability = "CAP_REFLECT"  // Uses package reflect
)

// riskyCapabilities are the capabilities whose appearance is an escalation.
var riskyCapabilities = map[Capability]bool{
	CapExec: true, CapNetwork: true, CapUnsafe: true, CapCgo: true, CapPlugin: true, CapEnv: true, CapFSWrite: true,
}

// ModuleCapabilities lists what a dependency module does from reachable code.
type ModuleCapabilities struct {
	Module       string                `json:"module"`
	Version      string                `json:"version,omitempty"`
	Capabilities []Capability          `json:"capabilities"`
	Evidence     map[Capability]string `json:"evidence,omitempty"`
}

// CapabilityReport holds the capabilities of every dependency module with
// code reachable from the program, sorted by module path.
type CapabilityReport struct {
	Modules []ModuleCapabilities `json:"modules"`
}

// Module returns the entry for path, if present.
func (r *CapabilityReport) Module(path string) (ModuleCapabilities, bool) {
	for _, m := range r.Modules {
		if m.Module == path {
			return m, true
		}
	}
	return ModuleCapabilities{}, false
}

// AnalyzeCapabilities computes the capabilities that dependency modules
// exercise from functions reachable from the program's entry points. Calls
// into the standard library are classified directly, or by following its
// static calls a few levels deep. Package imports of unsafe, cgo, plugin and
// reflect count when the importing package has reachable code.
func AnalyzeCapabilities(ws *workspace.Workspace, graph *codessa.GraphBundle) (*CapabilityReport, error) {
	if ws == nil || graph == nil || graph.Program == nil {
		return nil, fmt.Errorf("capability analysis needs a loaded workspace and call graph")
	}
	a := &capabilityAnalysis{graph: graph, modules: map[string]*packages.Module{}, byModule: map[string]*moduleEvidence{}}
	for _, pkg := range ws.AllPkgs {
		if pkg.Module != nil {
			a.modules[pkg.PkgPath] = pkg.Module
		}
	}
	a.collector = &capabilityCollector{graph: graph, memo: map[*ssa.Function][]capabilityHit{}, isStdlib: a.isStdlib}

	reachable := graph.ReachableFrom(programRoots(graph))
	fns := make([]*ssa.Function, 0, len(reachable))
	for fn := range reachable {
		fns = append(fns, fn)
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].String() < fns[j].String() })
	reachedPkgs := map[*ssa.Package]*packages.Module{}
	for _, fn := range fns {
		if m := a.externalModule(fn); m != nil {
			reachedPkgs[fn.Package()] = m
			a.scanCalls(fn, a.evidence(m))
		}
	}
	for pkg, m := range reachedPkgs {
		a.scanImports(pkg, a.evidence(m))
	}
	return a.report(), nil
}

// importCapabilities are the capabilities granted by importing a package.
var importCapabilities = map[string]Capability{"unsafe": CapUnsafe, "runtime/cgo": CapCgo, "plugin": CapPlugin, "reflect": CapReflect}

// capabilityAnalysis accumulates per-module capability evidence.
type capabilityAnalysis struct {
	graph     *codessa.GraphBundle
	modules   map[string]*packages.Module
	byModule  map[string]*moduleEvidence
	collector *capabilityCollector
}

type moduleEvidence struct {
	version  string
	evidence map[Capability]string
}

// record keeps the lexically smallest evidence for deterministic output.
func (e *moduleEvidence) record(cap Capability, evidence string) {
	if prev, ok := e.evidence[cap]; !ok || evidence < prev {
		e.evidence[cap] = evidence
	}
}

// externalModule returns the dependency module that declares fn, or nil for
// the main module and the standard library.
func (a *capabilityAnalysis) externalModule(fn *ssa.Function) *packages.Module {
	pkg := fn.Package()
	if pkg == nil {
		return nil
	}
	if m := a.modules[pkg.Pkg.Path()]; m != nil && !m.Main {
		return m
	}
	return nil
}

func (a *capabilityAnalysis) isStdlib(fn *ssa.Function) bool {
	pkg := fn.Package()
	return pkg != nil && a.modules[pkg.Pkg.Path()] == nil && pkg.Pkg.Name() != "main"
}

func (a *capabilityAnalysis) evidence(m *packages.Module) *moduleEvidence {
	e := a.byModule[m.Path]
	if e == nil {
		version := m.Version
		if m.Replace != nil && m.Replace.Version != "" {
			version = m.Replace.Version
		}
		e = &moduleEvidence{version: version, evidence: map[Capability]string{}}
		a.byModule[m.Path] = e
	}
	return e
}

// scanCalls classifies the standard library calls made by fn.
func (a *capabilityAnalysis) scanCalls(fn *ssa.Function, e *moduleEvidence) {
	node := a.graph.CallGraph.Nodes[fn]
	if node == nil {
		return
	}
	for _, edge := range node.Out {
		callee := edge.Callee.Func
		if callee == nil || !a.isStdlib(callee) || isPackageInit(callee) {
			continue
		}
		for _, hit := range a.collector.capabilities(callee, 0) {
			e.record(hit.cap, displayName(fn)+" -> "+hit.path)
		}
	}
}

func (a *capabilityAnalysis) scanImports(pkg *ssa.Package, e *moduleEvidence) {
	for _, imp := range pkg.Pkg.Imports() {
		if cap, ok := importCapabilities[imp.Path()]; ok {
			e.record(cap, pkg.Pkg.Path()+" imports "+imp.Path())
		}
	}
}

func (a *capabilityAnalysis) report() *CapabilityReport {
	report := &CapabilityReport{}
	for path, e := range a.byModule {
		mc := ModuleCapabilities{Module: path, Version: e.version, Capabilities: []Capability{}}
		for cap := range e.evidence {
			mc.Capabilities = append(mc.Capabilities, cap)
		}
		slices.Sort(mc.Capabilities)
		if len(e.evidence) > 0 {
			mc.Evidence = e.evidence
		}
		report.Modules = append(report.Modules, mc)
	}
	sort.Slice(report.Modules, func(i, j int) bool { return report.Modules[i].Module < report.Modules[j].Module })
	return report
}

type capabilityHit struct {
	cap  Capability
	path string
}

type capabilityCollector struct {
	graph    *codessa.GraphBundle
	memo     map[*ssa.Function][]capabilityHit
	isStdlib func(*ssa.Function) bool
}

const stdlibCallDepth = 4

// capabilities classifies a standard library function, following its static
// calls inside the standard library.
func (c *capabilityCollector) capabilities(fn *ssa.Function, depth int) []capabilityHit {
	if hits, ok := c.memo[fn]; ok {
		return hits
	}
	c.memo[fn] = nil // breaks cycles
	name := displayName(fn)
	var hits []capabilityHit
	if cap, ok := primitiveCapability(fn); ok {
		hits = []capabilityHit{{cap: cap, path: name}}
	} else if depth < stdlibCallDepth {
		seen := map[Capability]bool{}
		if node := c.graph.CallGraph.Nodes[fn]; node != nil {
			for _, e := range node.Out {
				callee := e.Callee.Func
				// Only static calls are followed: dynamic calls of function
				// values inside the standard library (sync.Once.Do, sort.Slice,
				// ...) resolve to every callback in the program.
				if callee == nil || e.Site == nil || e.Site.Common().StaticCallee() == nil || !c.isStdlib(callee) || isPackageInit(callee) {
					continue
				}
				for _, h := range c.capabilities(callee, depth+1) {
					if !seen[h.cap] {
						seen[h.cap] = true
						hits = append(hits, capabilityHit{cap: h.cap, path: name + " -> " + h.path})
					}
				}
			}
		}
	}
	c.memo[fn] = hits
	return hits
}

// isPackageInit reports whether fn is a package initializer. Standard library
// initialization is not attributed to the importing module.
func isPackageInit(fn *ssa.Function) bool {
	return fn.Signature.Recv() == nil && fn.Parent() == nil && (fn.Name() == "init" || strings.HasPrefix(fn.Name(), "init#"))
}

// displayName renders fn as "pkg/path.Func" or "pkg/path.Type.Method".
func displayName(fn *ssa.Function) string {
	pkg, name := symbolOf(fn)
	if pkg == "" {
		return fn.String()
	}
	return pkg + "." + name
}

var (
	osWrite = map[string]bool{"Create": true, "WriteFile": true, "OpenFile": true, "Remove": true, "RemoveAll": true, "Rename": true,
		"Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true, "Mkdir": true, "MkdirAll": true, "MkdirTemp": true, "CreateTemp": true,
		"Symlink": true, "Link": true, "Truncate": true}
	osRead = map[string]bool{"Open": true, "ReadFile": true, "ReadDir": true, "DirFS": true}
	osEnv  = map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true}
)

// exactPrimitives maps fully qualified standard library functions and methods
// to the capability they exercise.
var exactPrimitives = map[string]Capability{
	"syscall.Exec": CapExec, "syscall.ForkExec": CapExec, "syscall.StartProcess": CapExec,
	"os.StartProcess": CapExec,
	"plugin.Open":     CapPlugin,
	"net/http.Get":    CapNetwork, "net/http.Post": CapNetwork, "net/http.Head": CapNetwork, "net/http.PostForm": CapNetwork,
	"net/http.Serve": CapNetwork, "net/http.ServeTLS": CapNetwork,
	"net/http.Client.Do": CapNetwork, "net/http.Client.Get": CapNetwork, "net/http.Client.Post": CapNetwork,
	"net/http.Client.Head": CapNetwork, "net/http.Client.PostForm": CapNetwork,
	"net/http.Server.Serve": CapNetwork, "net/http.Server.ServeTLS": CapNetwork,
	"net/http.Transport.RoundTrip": CapNetwork,
}

// execStarters are the os/exec functions and Cmd methods that create or start
// a process; error types and helpers such as LookPath do not.
var execStarters = map[string]map[string]bool{
	"":    {"Command": true, "CommandContext": true},
	"Cmd": {"Start": true, "Run": true, "Output": true, "CombinedOutput": true},
}

// netDialers are the receivers of package net whose Dial, Listen and Lookup
// methods open connections ("" stands for package-level functions).
var netDialers = map[string]bool{"": true, "Dialer": true, "ListenConfig": true, "Resolver": true}

// primitiveCapability classifies the standard library entry points that
// perform privileged operations.
func primitiveCapability(fn *ssa.Function) (Capability, bool) {
	pkg, name := symbolOf(fn)
	if c, ok := exactPrimitives[pkg+"."+name]; ok {
		return c, true
	}
	recv, method, isMethod := strings.Cut(name, ".")
	if !isMethod {
		recv, method = "", name
	}
	dialing := strings.HasPrefix(method, "Dial") || strings.HasPrefix(method, "Listen") || strings.HasPrefix(method, "Lookup")
	switch pkg {
	case "os/exec":
		return CapExec, execStarters[recv][method]
	case "os":
		if recv == "" {
			return osCapability(method)
		}
	case "net":
		return CapNetwork, dialing && netDialers[recv]
	case "net/http":
		return CapNetwork, (recv == "" || recv == "Server") && strings.HasPrefix(method, "ListenAndServe")
	case "net/rpc", "net/smtp", "crypto/tls":
		return CapNetwork, dialing || method == "SendMail"
	}
	return "", false
}

// osCapability classifies the package-level functions of package os.
func osCapability(name string) (Capability, bool) {
	switch {
	case osWrite[name]:
		return CapFSWrite, true
	case osRead[name]:
		return CapFSRead, true
	case osEnv[name]:
		return CapEnv, true
	}
	return "", false
}

// CapabilityLock records the approved capabilities of each dependency module.
type CapabilityLock struct {
	Version int                     `json:"version"`
	Modules map[string][]Capability `json:"modules"`
}

// Lock returns a lock file approving the report's capabilities.
func (r *CapabilityReport) Lock() *CapabilityLock {
	lock := &CapabilityLock{Version: 1, Modules: map[string][]Capability{}}
	for _, m := range r.Modules {
		lock.Modules[m.Module] = append([]Capability{}, m.Capabilities...)
	}
	return lock
}

// LoadCapabilityLock reads a lock file.
func LoadCapabilityLock(path string) (*CapabilityLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock CapabilityLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if lock.Modules == nil {
		lock.Modules = map[string][]Capability{}
	}
	return &lock, nil
}

// WriteCapabilityLock writes lock as indented, deterministic JSON.
func WriteCapabilityLock(path string, lock *CapabilityLock) error {
	for _, caps := range lock.Modules {
		slices.Sort(caps)
	}
	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// CapabilityEscalation is a risky capability a module gained since the lock.
type CapabilityEscalation struct {
	Module   string
	Version  string
	New      []Capability
	Severity result.Severity
	Evidence []string
	NewDep   bool
}

// DiffCapabilities reports risky capabilities present in current but not
// approved for the same module in lock. Execution, cgo, plugins and the
// combination of environment access with networking are critical.
func DiffCapabilities(lock *CapabilityLock, current *CapabilityReport) []CapabilityEscalation {
	if lock == nil {
		lock = &CapabilityLock{Modules: map[string][]Capability{}}
	}
	var out []CapabilityEscalation
	for _, m := range current.Modules {
		approved, known := lock.Modules[m.Module]
		var gained []Capability
		for _, cap := range m.Capabilities {
			if riskyCapabilities[cap] && !slices.Contains(approved, cap) {
				gained = append(gained, cap)
			}
		}
		if len(gained) == 0 {
			continue
		}
		esc := CapabilityEscalation{Module: m.Module, Version: m.Version, New: gained, Severity: result.SeverityHigh, NewDep: !known}
		has := func(c Capability) bool { return slices.Contains(m.Capabilities, c) }
		for _, cap := range gained {
			switch cap {
			case CapExec, CapCgo, CapPlugin:
				esc.Severity = result.SeverityCritical
			case CapEnv, CapNetwork:
				if has(CapEnv) && has(CapNetwork) {
					esc.Severity = result.SeverityCritical
				}
			}
			if ev := m.Evidence[cap]; ev != "" {
				esc.Evidence = append(esc.Evidence, ev)
			}
		}
		out = append(out, esc)
	}
	return out
}

// EscalationIssues converts escalations into issues anchored at the lock file.
func EscalationIssues(escalations []CapabilityEscalation, lockPath string) []result.Issue {
	var out []result.Issue
	for _, e := range escalations {
		names := make([]string, len(e.New))
		for i, c := range e.New {
			names[i] = string(c)
		}
		what := "gained"
		if e.NewDep {
			what = "is a new dependency with"
		}
		desc := fmt.Sprintf("Module %s %s %s %s not approved in %s.", e.Module, e.Version, what, strings.Join(names, ", "), lockPath)
		if len(e.Evidence) > 0 {
			desc += " Call path: " + strings.Join(e.Evidence, "; ") + "."
		}
		out = append(out, result.Issue{
			ID: "supply-chain-capability-escalation", Title: "Dependency Capability Escalation", Severity: e.Severity, Category: "supply-chain",
			CWE: "CWE-506", OWASP: "A03:2025", Confidence: 1, Description: desc,
			Location:   result.NewLocationFromPos(token.Position{Filename: lockPath, Line: 1}, "", ""),
			Suggestion: "Review the dependency change. If the new behaviour is expected, approve it with 'codex caps lock'.",
		})
	}
	return out
}
