package builtin

import (
	"go/ast"
	"path"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var commandInjectionMeta = ruleMeta{
	ID: "command-injection", Title: "OS Command Injection", Severity: result.SeverityHigh, CWE: "CWE-78", OWASP: "A05:2025",
	Confidence: 0.8,
	Suggestion: "Avoid invoking a shell. Run a fixed executable and pass validated values as separate arguments.",
	References: []string{"https://cwe.mitre.org/data/definitions/78.html"},
}

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true}

var shellFlags = map[string]bool{"-c": true, "/c": true, "/C": true, "-Command": true, "-command": true, "/k": true, "/K": true}

// RegisterCommandExecRule reports shells invoked with dynamic scripts and
// processes started from non-constant executables.
func RegisterCommandExecRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{commandInjectionMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := calleeFunc(info, call)
				args := call.Args
				switch {
				case isFunc(fn, "os/exec", "Command"):
				case isFunc(fn, "os/exec", "CommandContext") && len(args) > 0:
					args = args[1:]
				case isFunc(fn, "syscall", "Exec", "ForkExec") || isFunc(fn, "os", "StartProcess"):
					if len(args) > 0 && !isConst(info, args[0]) {
						r.report(commandInjectionMeta, args[0], "Process started from a non-constant executable path.")
					}
					return true
				default:
					return true
				}
				if len(args) == 0 {
					return true
				}
				bin, constBin := constString(info, args[0])
				if !constBin {
					r.report(commandInjectionMeta, args[0], "Command executable is not a constant.")
					return true
				}
				if !shells[strings.ToLower(path.Base(bin))] {
					return true
				}
				for i := 1; i+1 < len(args); i++ {
					flag, ok := constString(info, args[i])
					if !ok || !shellFlags[flag] {
						continue
					}
					script := args[i+1]
					if !isConst(info, script) {
						r.reportWith(commandInjectionMeta, script, "Shell "+bin+" executes a dynamically built script.", result.SeverityCritical, nil)
					}
					break
				}
				return true
			})
		}
	})
}
