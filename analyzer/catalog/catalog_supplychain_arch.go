package catalog

// CategorySuppression is the category of findings about suppressions.
const CategorySuppression = "suppression"

// supplyChainDocs covers dependency, license and go.mod rules.
var supplyChainDocs = []RuleDoc{
	{
		ID: "dependency-vulnerability", Code: "CS053", Title: "Vulnerable Dependency", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-1395", OWASP: "A03:2025",
		Summary:     "A required module or the Go standard library version has a known vulnerability.",
		Explanation: "Modules and the toolchain version are checked against OSV, the Go vulnerability database and, with GITHUB_TOKEN, GitHub advisories. When the advisory names symbols, the call graph decides whether they are reachable; unreachable findings are lowered to Low and marked not_affected in VEX output. The severity follows the advisory.",
		BadExample:  `require golang.org/x/net v0.20.0 // affected by a published advisory`,
		GoodExample: `require golang.org/x/net v0.38.0 // first fixed version or later`,
		References:  []string{"https://osv.dev", "https://pkg.go.dev/vuln/"},
	},
	{
		ID: "supply-chain-capability-escalation", Code: "CS054", Title: "Dependency Capability Escalation", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-506", OWASP: "A03:2025",
		Summary:     "A dependency's reachable code uses a capability the lock file does not approve.",
		Explanation: "codex-cli caps lock records which privileged capabilities (exec, network, file system, environment, unsafe, cgo, plugins) each dependency uses from reachable code. An upgrade that suddenly starts running processes or opening connections is how compromised packages behave. Escalations to exec, cgo or plugins, or to both environment and network access, are Critical.",
		BadExample: `// .codexsentinel.caps.json approves only CAP_FS_READ for github.com/acme/parser,
// but the new version calls os/exec.Command from code your program reaches.`,
		GoodExample: `// Review the dependency change; if it is expected, approve it:
//   codex-cli caps lock`,
		References: []string{cweURL + "506.html"},
	},
	{
		ID: "license-denied", Code: "CS055", Title: "Denied License Detected", Category: CategoryLicense, DefaultSeverity: high,
		Summary:     "A dependency's license is on the deny list.",
		Explanation: "License files in the module cache or vendor/ are classified into SPDX identifiers and compared with dependencies.allow_licenses and deny_licenses. Copyleft licenses such as AGPL-3.0 can impose obligations on the whole program.",
		BadExample:  `require github.com/acme/agpl-lib v1.2.0 // AGPL-3.0`,
		GoodExample: `require github.com/acme/mit-lib v1.4.0 // MIT`,
		References:  []string{"https://spdx.org/licenses/"},
	},
	{
		ID: "high-entropy-string", Code: "CS056", Title: "High Entropy String in Vendored Code", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-798", OWASP: "A07:2025",
		Summary:     "Vendored dependency code contains a string that looks like a secret.",
		Explanation: "Long strings with high Shannon entropy in vendor/ are often embedded credentials or keys that were committed upstream or by a patch.",
		BadExample: `// vendor/github.com/acme/client/config.go
const apiKey = "Zx9Lq2...44 random characters..."`,
		GoodExample: `// vendor/github.com/acme/client/config.go
apiKey := os.Getenv("ACME_API_KEY")`,
		References: []string{cweURL + "798.html"},
	},
	{
		ID: "dependency-typosquatting", Code: "CS057", Title: "Possible Typosquatted Dependency", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-1357", OWASP: "A03:2025",
		Summary:     "A required module path is one or two characters away from a well-known module.",
		Explanation: "Vulnerability scanners only know published advisories, so a freshly registered look-alike module, or a module name that never existed until someone registered it after seeing it suggested, shows zero vulnerabilities. The check compares requirements with about 300 widely used modules, counting transpositions and look-alike characters as one edit. Modules under organization-controlled domains, of your own account, or under allowed_prefixes are not compared.",
		BadExample:  `require github.com/gin-gonlc/gin v1.10.0`,
		GoodExample: `require github.com/gin-gonic/gin v1.10.0`,
		References:  []string{cweURL + "1357.html"},
	},
	{
		ID: "gomod-local-replace", Code: "CS058", Title: "Local Replace Directive in go.mod", Category: CategorySupplyChain, DefaultSeverity: medium,
		CWE: "CWE-1357", OWASP: "A03:2025",
		Summary:     "A replace directive points at a local directory.",
		Explanation: "A directory replacement exists only on the machine that wrote it; on CI or another developer's machine the build fails or uses different code. Use a go.work file for local development, or replace with a published version.",
		BadExample:  `replace example.com/shared => ../shared`,
		GoodExample: `replace example.com/shared => example.com/shared v1.4.2`,
		References:  []string{"https://go.dev/ref/mod#go-mod-file-replace"},
	},
	{
		ID: "gomod-missing-checksum", Code: "CS059", Title: "Dependency Without go.sum Checksum", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-353", OWASP: "A03:2025",
		Summary:     "A direct requirement has no content hash in go.sum.",
		Explanation: "go.sum pins the exact content of each module version. Without it the content is not verified against what was reviewed, and builds depend on whatever the proxy or origin serves.",
		BadExample:  `// go.mod requires github.com/google/uuid v1.6.0, but go.sum has no line for it`,
		GoodExample: `// go mod tidy, then commit go.sum:
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=`,
		References: []string{"https://go.dev/ref/mod#go-sum-files"},
	},
	{
		ID: "dependency-policy-denied", Code: "CS060", Title: "Dependency Violates Module Policy", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-1357", OWASP: "A03:2025",
		Summary:     "A module matches denied_prefixes or falls outside allowed_prefixes.",
		Explanation: "dependencies.denied_prefixes blocks modules and organizations, and a non-empty allowed_prefixes allows only the listed ones, for direct and indirect requirements alike.",
		BadExample: `# codex.yaml
dependencies:
  denied_prefixes: [github.com/dgrijalva]
# go.mod
require github.com/dgrijalva/jwt-go v3.2.0+incompatible`,
		GoodExample: `require github.com/golang-jwt/jwt/v5 v5.2.1`,
		References:  []string{cweURL + "1357.html"},
	},
	{
		ID: "dependency-young-module", Code: "CS061", Title: "Recently Published Dependency Version", Category: CategorySupplyChain, DefaultSeverity: medium,
		CWE: "CWE-1357", OWASP: "A03:2025",
		Summary:     "A required version was published less than min_module_age_days ago.",
		Explanation: "Compromised maintainer accounts and malicious packages are usually found within days of publication. Waiting before adopting a new release gives that process time. The publication time comes from the module proxy; modules under allowed_prefixes and of your own account are skipped.",
		BadExample:  `require github.com/acme/fresh v1.0.0 // published two hours ago`,
		GoodExample: `require github.com/acme/fresh v0.9.4 // published three weeks ago and reviewed`,
		References:  []string{"https://go.dev/ref/mod#goproxy-protocol"},
	},
	{
		ID: "dependency-retracted", Code: "CS062", Title: "Retracted Dependency Version", Category: CategorySupplyChain, DefaultSeverity: high,
		CWE: "CWE-1395", OWASP: "A03:2025",
		Summary:     "The required version is retracted by the module's authors.",
		Explanation: "Authors retract versions that are broken or were published by mistake, often for security reasons. The retraction and its rationale come from the go.mod of the module's latest version.",
		BadExample:  `require github.com/acme/broken v1.0.3 // retract [v1.0.0, v1.0.5] // critical security bug`,
		GoodExample: `require github.com/acme/broken v1.0.6`,
		References:  []string{"https://go.dev/ref/mod#go-mod-file-retract"},
	},
	{
		ID: "dependency-deprecated", Code: "CS063", Title: "Deprecated Dependency", Category: CategorySupplyChain, DefaultSeverity: medium,
		CWE: "CWE-1104", OWASP: "A03:2025",
		Summary:     "The module is marked deprecated by its authors.",
		Explanation: "A // Deprecated: comment on the module directive means the authors no longer maintain it, so future vulnerabilities will not be fixed. The notice usually names the replacement.",
		BadExample:  `require github.com/golang/protobuf v1.5.4 // Deprecated: use google.golang.org/protobuf`,
		GoodExample: `require google.golang.org/protobuf v1.36.0`,
		References:  []string{"https://go.dev/ref/mod#go-mod-file-module-deprecation"},
	},
}

// architectureDocs covers layer, cycle and boundary rules.
var architectureDocs = []RuleDoc{
	{
		ID: "arch-layer-violation", Code: "CS064", Title: "Layer Dependency Violation", Category: CategoryArchitecture, DefaultSeverity: low,
		Summary:     "A package imports a layer it may not depend on.",
		Explanation: "architecture.layers maps package patterns to layers and allowed_deps lists which layers each may import. A domain package importing a database adapter couples business rules to infrastructure and makes them hard to test.",
		BadExample: `// internal/domain/order.go
import "example.com/app/internal/repository"`,
		GoodExample: `// internal/domain/order.go declares the interface it needs
type OrderStore interface {
	Save(ctx context.Context, o Order) error
}`,
		References: []string{"https://go.dev/doc/modules/layout"},
	},
	{
		ID: "arch-import-cycle", Code: "CS065", Title: "Import Cycle", Category: CategoryArchitecture, DefaultSeverity: high,
		Summary:     "Packages of the module import each other in a cycle.",
		Explanation: "Packages that import each other, directly or through other packages, cannot be built: the go command refuses import cycles. The finding lists every package in the cycle so that the dependency to break is visible.",
		BadExample:  `// package a imports b, and package b imports a`,
		GoodExample: `// move the shared types into package c, imported by both a and b`,
		References:  []string{"https://go.dev/ref/spec#Import_declarations"},
	},
	{
		ID: "arch-god-struct", Code: "CS066", Title: "Oversized Struct", Category: CategoryArchitecture, DefaultSeverity: low,
		Summary:     "A struct has too many methods, or many fields combined with behavior.",
		Explanation: "A type with more than god_struct_max_methods methods, or more than god_struct_max_fields fields and several methods, usually mixes responsibilities and is hard to change safely. Plain data records with many fields are not reported.",
		BadExample: `type Service struct{ /* 25 fields */ }
// ... 30 methods covering billing, email and reporting`,
		GoodExample: `type Billing struct{ /* ... */ }
type Notifier struct{ /* ... */ }
type Reports struct{ /* ... */ }`,
	},
	{
		ID: "arch-boundary-type-leak", Code: "CS067", Title: "Infrastructure Type Crosses Layer Boundary", Category: CategoryArchitecture, DefaultSeverity: medium,
		Summary:     "A layer's exported API exposes types of a layer it should hide.",
		Explanation: "When a service method returns *sql.Rows or a gorm model, callers depend on the storage technology through it. Return domain types instead.",
		BadExample:  `func (s *UserService) Find(ctx context.Context, id int64) (*sql.Row, error)`,
		GoodExample: `func (s *UserService) Find(ctx context.Context, id int64) (domain.User, error)`,
	},
}

// metricsDocs covers code metrics and suppression hygiene.
var metricsDocs = []RuleDoc{
	{
		ID: "high-complexity", Code: "CS068", Title: "High Cyclomatic Complexity", Category: CategoryMetrics, DefaultSeverity: medium,
		Summary:     "A function's cyclomatic complexity exceeds metrics.max_cyclomatic.",
		Explanation: "Each branch doubles the paths to test and review. Functions above the threshold (default 15) are where bugs and missed security checks concentrate. Split the function or replace branches with lookups.",
		BadExample:  `func price(o Order) int { /* 20 nested if and switch branches */ }`,
		GoodExample: `func price(o Order) int {
	return base(o) + shipping(o) - discount(o)
}`,
	},
	{
		ID: "large-function", Code: "CS069", Title: "Large Function", Category: CategoryMetrics, DefaultSeverity: low,
		Summary:     "A function is longer than metrics.max_function_loc lines.",
		Explanation: "Long functions (default limit 80 lines) are hard to read in one screen and usually do several things. Extract steps into named functions.",
		BadExample:  `func handle(w http.ResponseWriter, r *http.Request) { /* 150 lines */ }`,
		GoodExample: `func handle(w http.ResponseWriter, r *http.Request) {
	req, err := decode(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, process(req))
}`,
	},
	{
		ID: "large-file", Code: "CS070", Title: "Large File", Category: CategoryMetrics, DefaultSeverity: low,
		Summary:     "A file is longer than metrics.max_file_loc lines.",
		Explanation: "Very long files (default limit 600 lines) usually hold several concerns. Split them by type or feature.",
		BadExample:  `// server.go: 1,800 lines of handlers, middleware and storage`,
		GoodExample: `// handlers.go, middleware.go, storage.go`,
	},
	{
		ID: "code-duplication", Code: "CS071", Title: "Duplicated Function Body", Category: CategoryMetrics, DefaultSeverity: low,
		Summary:     "Function bodies of at least metrics.min_duplicate_loc lines are identical.",
		Explanation: "Copied code drifts: a fix applied to one copy, often a security fix, is missed in the others. Extract the shared body.",
		BadExample: `func (a *Admin) audit(...) { /* 15 lines */ }
func (u *User) audit(...)  { /* the same 15 lines */ }`,
		GoodExample: `func audit(log Logger, ev Event) { /* 15 lines, once */ }`,
	},
	{
		ID: "global-variable", Code: "CS072", Title: "Mutable Global State", Category: CategoryMetrics, DefaultSeverity: low,
		Summary:     "A package variable is written at run time.",
		Explanation: "Package variables written after initialization are shared by every goroutine and test, which causes data races and order-dependent behavior. Constants, sentinel errors, compiled regular expressions, lookup tables that are never written and variables guarded by a mutex in the same var block are not reported.",
		BadExample: `var currentUser *User

func login(u *User) { currentUser = u }`,
		GoodExample: `type Session struct{ user *User }

func (s *Session) Login(u *User) { s.user = u }`,
	},
	{
		ID: "dead-code", Code: "CS073", Title: "Unused Function", Category: CategoryMetrics, DefaultSeverity: low,
		Summary:     "A function is unreachable from the program's entry points.",
		Explanation: "Unused functions still have to be read, maintained and kept secure. Reachability is computed on the call graph from main, init, tests and exported API.",
		BadExample:  `func legacyExport() { /* no callers */ }`,
		GoodExample: `// remove the function, or call it where it is needed`,
	},
	{
		ID: "ignore-missing-reason", Code: "CS074", Title: "Suppression Without Justification", Category: CategorySuppression, DefaultSeverity: low,
		Summary:     "A suppression gives no reason while suppression.require_ignore_reason is set.",
		Explanation: "Suppressions without a reason cannot be reviewed later. Add the reason after -- so that reviewers can judge whether it still holds.",
		BadExample: `//codex:ignore sql-injection
rows, err := db.Query(q)`,
		GoodExample: `//codex:ignore sql-injection -- q is built from the fixed column allowlist above
rows, err := db.Query(q)`,
	},
	{
		ID: "unauthorized-suppression-added", Code: "CS075", Title: "Unauthorized Security Suppression Added in Diff", Category: CategorySecurity, DefaultSeverity: critical,
		CWE: "CWE-693", OWASP: "A06:2025",
		Summary: "A change adds an inline ignore, an ignore-file entry or a setting that hides findings.",
		Explanation: "With --forbid-new-suppressions, lines added since the --diff reference (HEAD by default) are checked: //codex:ignore, //nolint and #nosec in Go comments, entries in the ignore file, and configuration that disables rules, excludes paths or relaxes thresholds. " +
			"Directive-like text in string literals, comments in the ignore file, tightened settings and suppressions that a removed line already contained are not reported. The finding cannot itself be suppressed; CI approves a reviewed change by setting CODEX_ALLOW_SUPPRESSIONS=1.",
		BadExample:  `rows, err := db.Query("SELECT * FROM users WHERE id = " + id) //codex:ignore sql-injection -- fix later`,
		GoodExample: `rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)`,
		References:  []string{cweURL + "693.html"},
	},
}
