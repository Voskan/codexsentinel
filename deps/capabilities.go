package deps

import (
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
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
	modules := map[string]*packages.Module{}
	for _, pkg := range ws.AllPkgs {
		if pkg.Module != nil {
			modules[pkg.PkgPath] = pkg.Module
		}
	}
	external := func(fn *ssa.Function) (*packages.Module, bool) {
		pkg := fn.Package()
		if pkg == nil {
			return nil, false
		}
		m := modules[pkg.Pkg.Path()]
		return m, m != nil && !m.Main
	}

	reachable := graph.ReachableFrom(programRoots(graph))
	isStdlib := func(fn *ssa.Function) bool {
		pkg := fn.Package()
		return pkg != nil && modules[pkg.Pkg.Path()] == nil && pkg.Pkg.Name() != "main"
	}
	c := &capabilityCollector{graph: graph, memo: map[*ssa.Function][]capabilityHit{}, isStdlib: isStdlib}
	type acc struct {
		version  string
		evidence map[Capability]string
	}
	byModule := map[string]*acc{}
	get := func(m *packages.Module) *acc {
		a := byModule[m.Path]
		if a == nil {
			version := m.Version
			if m.Replace != nil && m.Replace.Version != "" {
				version = m.Replace.Version
			}
			a = &acc{version: version, evidence: map[Capability]string{}}
			byModule[m.Path] = a
		}
		return a
	}
	record := func(a *acc, cap Capability, evidence string) {
		if prev, ok := a.evidence[cap]; !ok || evidence < prev {
			a.evidence[cap] = evidence
		}
	}
	reachedPkgs := map[*ssa.Package]*packages.Module{}
	fns := make([]*ssa.Function, 0, len(reachable))
	for fn := range reachable {
		fns = append(fns, fn)
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].String() < fns[j].String() })
	for _, fn := range fns {
		m, ok := external(fn)
		if !ok {
			continue
		}
		a := get(m)
		reachedPkgs[fn.Package()] = m
		node := graph.CallGraph.Nodes[fn]
		if node == nil {
			continue
		}
		for _, e := range node.Out {
			callee := e.Callee.Func
			if callee == nil || !isStdlib(callee) || isPackageInit(callee) {
				continue
			}
			for _, hit := range c.capabilities(callee, 0) {
				record(a, hit.cap, displayName(fn)+" -> "+hit.path)
			}
		}
	}
	for pkg, m := range reachedPkgs {
		a := get(m)
		for _, imp := range pkg.Pkg.Imports() {
			var cap Capability
			switch imp.Path() {
			case "unsafe":
				cap = CapUnsafe
			case "runtime/cgo":
				cap = CapCgo
			case "plugin":
				cap = CapPlugin
			case "reflect":
				cap = CapReflect
			default:
				continue
			}
			record(a, cap, pkg.Pkg.Path()+" imports "+imp.Path())
		}
	}

	report := &CapabilityReport{}
	for path, a := range byModule {
		mc := ModuleCapabilities{Module: path, Version: a.version, Capabilities: []Capability{}}
		for cap := range a.evidence {
			mc.Capabilities = append(mc.Capabilities, cap)
		}
		slices.Sort(mc.Capabilities)
		if len(a.evidence) > 0 {
			mc.Evidence = a.evidence
		}
		report.Modules = append(report.Modules, mc)
	}
	sort.Slice(report.Modules, func(i, j int) bool { return report.Modules[i].Module < report.Modules[j].Module })
	return report, nil
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
				if callee == nil || e.Site == nil || e.Site.Common().IsInvoke() || !c.isStdlib(callee) || isPackageInit(callee) {
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

// primitiveCapability classifies the standard library entry points that
// perform privileged operations.
func primitiveCapability(fn *ssa.Function) (Capability, bool) {
	pkg, name := symbolOf(fn)
	recv, method, isMethod := strings.Cut(name, ".")
	if !isMethod {
		method = name
		recv = ""
	}
	dialing := strings.HasPrefix(method, "Dial") || strings.HasPrefix(method, "Listen") || strings.HasPrefix(method, "Lookup")
	switch pkg {
	case "os/exec":
		if token.IsExported(method) {
			return CapExec, true
		}
	case "syscall":
		switch method {
		case "Exec", "ForkExec", "StartProcess":
			return CapExec, true
		}
	case "os":
		switch {
		case recv == "" && method == "StartProcess":
			return CapExec, true
		case recv == "" && osWrite[method]:
			return CapFSWrite, true
		case recv == "" && osRead[method]:
			return CapFSRead, true
		case recv == "" && osEnv[method]:
			return CapEnv, true
		}
	case "net":
		if dialing && (recv == "" || recv == "Dialer" || recv == "ListenConfig" || recv == "Resolver") {
			return CapNetwork, true
		}
	case "net/http":
		switch {
		case recv == "" && (method == "Get" || method == "Post" || method == "Head" || method == "PostForm" || strings.HasPrefix(method, "ListenAndServe") || method == "Serve" || method == "ServeTLS"):
			return CapNetwork, true
		case recv == "Client" && (method == "Do" || method == "Get" || method == "Post" || method == "Head" || method == "PostForm"):
			return CapNetwork, true
		case recv == "Server" && (strings.HasPrefix(method, "ListenAndServe") || method == "Serve" || method == "ServeTLS"):
			return CapNetwork, true
		case recv == "Transport" && method == "RoundTrip":
			return CapNetwork, true
		}
	case "net/rpc", "net/smtp", "crypto/tls":
		if dialing || method == "SendMail" {
			return CapNetwork, true
		}
	case "plugin":
		if method == "Open" {
			return CapPlugin, true
		}
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
			ID: "supply-chain-capability-escalation", Title: "Dependency Capability Escalation", Severity: e.Severity, Category: "security",
			CWE: "CWE-506", Confidence: 1, Description: desc,
			Location:   result.NewLocationFromPos(token.Position{Filename: lockPath, Line: 1}, "", ""),
			Suggestion: "Review the dependency change. If the new behaviour is expected, approve it with 'codex caps lock'.",
		})
	}
	return out
}
