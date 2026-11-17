# Examples

Each example below shows code that CodexSentinel reports and a fixed version
that it does not. The findings are the actual output of
`codex-cli scan . --format json`, shortened to file, line, rule and message.

## Contents

- [SQL injection across functions](#sql-injection-across-functions)
- [Command injection](#command-injection)
- [Path traversal and os.Root](#path-traversal-and-osroot)
- [Server-side request forgery](#server-side-request-forgery)
- [Cross-site scripting](#cross-site-scripting)
- [Template injection](#template-injection)
- [NoSQL injection](#nosql-injection)
- [gRPC requests](#grpc-requests)
- [CSRF and http.CrossOriginProtection](#csrf-and-httpcrossoriginprotection)
- [Secrets in logs](#secrets-in-logs)
- [Server timeouts](#server-timeouts)
- [Network calls inside a transaction](#network-calls-inside-a-transaction)
- [Excessive data exposure and mass assignment](#excessive-data-exposure-and-mass-assignment)
- [Automatic fixes](#automatic-fixes)
- [Architecture layers](#architecture-layers)
- [Custom taint sinks](#custom-taint-sinks)
- [Custom YAML rule](#custom-yaml-rule)
- [Pull request workflow](#pull-request-workflow)
- [Continuous integration](#continuous-integration)
- [OpenVEX with Trivy and Grype](#openvex-with-trivy-and-grype)

## SQL injection across functions

```go
type Store struct{ db *sql.DB }

func (s *Store) FindUser(name string) (*sql.Rows, error) {
	return s.db.Query("SELECT id FROM users WHERE name = '" + name + "'")
}

func (s *Store) FindUserSafe(name string) (*sql.Rows, error) {
	return s.db.Query("SELECT id FROM users WHERE name = $1", name)
}

func Handler(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = s.FindUser(r.URL.Query().Get("name"))
		_, _ = s.FindUserSafe(r.URL.Query().Get("name"))
	}
}
```

```text
sqlx/sqlx.go:11 sql-injection HIGH  Untrusted data flows into a SQL query (untrusted input returned by (net/url.Values).Get)
  source  sqlx/sqlx.go:20  untrusted input returned by (net/url.Values).Get
  call    sqlx/sqlx.go:20  passed to Store.FindUser
  param   sqlx/sqlx.go:10  parameter name of Store.FindUser
  sink    sqlx/sqlx.go:11  reaches (database/sql.DB).Query
```

The source is in the handler and the sink is in another method. The trace
connects them; in SARIF it is a code flow. The parameterized query in
`FindUserSafe` is not reported.

## Command injection

```go
func Convert(w http.ResponseWriter, r *http.Request) {
	file := r.FormValue("file")
	_ = exec.CommandContext(r.Context(), "sh", "-c", "convert "+file+" out.png").Run()
}

func ConvertSafe(w http.ResponseWriter, r *http.Request) {
	file := r.FormValue("file")
	_ = exec.CommandContext(r.Context(), "convert", "--", file, "out.png").Run()
}
```

```text
cmdx/cmdx.go:10 command-injection CRITICAL  Untrusted data flows into an operating system command (untrusted input returned by (net/http.Request).FormValue)
```

Arguments passed to a fixed program other than a shell cannot inject
commands, so `ConvertSafe` is not reported. A non-constant program name, or
a shell such as `sh -c`, is.

## Path traversal and os.Root

```go
const baseDir = "/srv/files"

func Download(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(filepath.Join(baseDir, r.URL.Query().Get("name")))
	// ...
}

func DownloadSafe(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot(baseDir) // Go 1.24
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	f, err := root.Open(r.URL.Query().Get("name"))
	// ...
}
```

```text
pathx/pathx.go:13 path-traversal HIGH  Untrusted data flows into a filesystem path (untrusted input returned by (net/url.Values).Get)
```

`filepath.Join` does not stop `..` or absolute paths, and the handler could
read any file. `os.Root` confines every access to the directory and also
rejects symlinks that escape it, so `DownloadSafe` is not reported.

Paths from environment variables and command-line arguments are not reported
for path traversal; the operator of a CLI tool chooses them.

## Server-side request forgery

```go
var client = &http.Client{}

func Preview(w http.ResponseWriter, r *http.Request) {
	resp, err := client.Get(r.FormValue("url"))
	// ...
}

func Avatar(w http.ResponseWriter, r *http.Request) {
	u := url.URL{Scheme: "https", Host: "avatars.example.com", Path: "/" + url.PathEscape(r.FormValue("user"))}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	resp, err := client.Do(req)
	// ...
}
```

```text
ssrfx/ssrfx.go:11 ssrf HIGH  Untrusted data flows into an outbound HTTP request URL (untrusted input returned by (net/http.Request).FormValue)
ssrfx/ssrfx.go:11 context-propagation-missing MEDIUM  Get ignores the incoming context; use http.NewRequestWithContext.
```

A URL with a constant scheme and host is not reported, even when its path or
query contains request data. The host is constant whether it comes from a
string prefix, a `fmt.Sprintf` format or a `url.URL` literal.

## Cross-site scripting

```go
func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", r.FormValue("name"))
}

var page = template.Must(template.New("p").Parse("<h1>Hello, {{.}}</h1>"))

func HelloSafe(w http.ResponseWriter, r *http.Request) {
	_ = page.Execute(w, r.FormValue("name")) // html/template escapes the value
}
```

```text
xssx/xssx.go:10 xss HIGH  Untrusted data flows into an HTTP response (untrusted input returned by (net/http.Request).FormValue)
```

## Template injection

```go
var greeting = template.Must(template.New("greet").Parse("<p>Hello {{.}}</p>"))

func Greet(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("greet").Parse("<p>Hello " + r.FormValue("name") + "</p>")
	if err != nil {
		return
	}
	_ = tmpl.Execute(w, nil)
}

func GreetSafe(w http.ResponseWriter, r *http.Request) {
	_ = greeting.Execute(w, r.FormValue("name"))
}
```

```text
pages/pages.go:11 template-injection HIGH  Untrusted data flows into template source text (untrusted input returned by (net/http.Request).FormValue)
  source  pages/pages.go:11  untrusted input returned by (net/http.Request).FormValue
  sink    pages/pages.go:11  reaches (html/template.Template).Parse
```

`html/template` escapes the data passed to `Execute`, not the template text:
input parsed as a template can call methods of the data and emit any markup.
`GreetSafe` parses a constant template once and passes the name as data.

## NoSQL injection

```go
var hget = redis.NewScript("return redis.call('HGET', KEYS[1], ARGV[1])")

func (h *Handler) Counter(w http.ResponseWriter, r *http.Request) {
	field := r.FormValue("field")
	h.rdb.Eval(r.Context(), "return redis.call('HGET', 'stats', '"+field+"')", nil)
	hget.Run(r.Context(), h.rdb, []string{"stats"}, field)
}

func (h *Handler) Orders(w http.ResponseWriter, r *http.Request) {
	owner := r.FormValue("owner")
	_, _ = h.orders.CountDocuments(bson.M{"$where": "this.owner == '" + owner + "'"})
	_, _ = h.orders.CountDocuments(bson.M{"owner": owner})
}
```

```text
stats/stats.go:23 nosql-injection HIGH  Untrusted data flows into a Redis Lua script (untrusted input returned by (net/http.Request).FormValue)
  source  stats/stats.go:22  untrusted input returned by (net/http.Request).FormValue
  sink    stats/stats.go:23  reaches (github.com/redis/go-redis/v9.cmdable).Eval
stats/stats.go:29 nosql-injection HIGH  MongoDB $where runs JavaScript built from HTTP request input on the database server.
```

The script loaded once with `redis.NewScript` receives the field in `ARGV`,
and `bson.M{"owner": owner}` sends the owner as a value, so neither is
reported.

## gRPC requests

Request messages of gRPC and Connect handlers are untrusted input. The
generated getters are followed like any other function:

```go
type Server struct {
	userpb.UnimplementedUserServiceServer
	DB *sql.DB
}

func (s *Server) GetUser(ctx context.Context, req *userpb.GetUserRequest) (*userpb.UserResponse, error) {
	var resp userpb.UserResponse
	err := s.find(ctx, req.GetFilter()).Scan(&resp.Name)
	return &resp, err
}

func (s *Server) find(ctx context.Context, filter string) *sql.Row {
	return s.DB.QueryRowContext(ctx, "SELECT name FROM users WHERE "+filter)
}
```

```text
usersvc/server.go:22 sql-injection HIGH  Untrusted data flows into a SQL query (untrusted input received by Server.GetUser as parameter req)
  source  usersvc/server.go:15  untrusted input received by Server.GetUser as parameter req
  call    usersvc/server.go:17  passed to GetUserRequest.GetFilter
  param   userpb/user_grpc.pb.go:12  parameter x of GetUserRequest.GetFilter
  return  usersvc/server.go:17  returned from GetUserRequest.GetFilter
  call    usersvc/server.go:17  passed to Server.find
  param   usersvc/server.go:21  parameter filter of Server.find
  sink    usersvc/server.go:22  reaches (database/sql.DB).QueryRowContext
```

An exported method is treated as a handler when its receiver embeds a
generated `Unimplemented...Server` or `Unsafe...Server` type, or when it has
the shape of a unary handler, `func(context.Context, *pb.Request)
(*pb.Response, error)`. Request messages received on server streams are
untrusted as well.

## CSRF and http.CrossOriginProtection

```go
func transfer(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("session"); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer", transfer)
	return mux
}
```

```text
csrfx/csrfx.go:15 csrf-missing-protection MEDIUM  State-changing route "POST /transfer" uses cookie-based sessions without cross-origin request protection.
```

The fix with Go 1.25 needs no extra dependency:

```go
func Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer", transfer)
	return http.NewCrossOriginProtection().Handler(mux)
}
```

## Secrets in logs

```go
func Login(u User, password string) {
	slog.Info("login attempt", "user", u.Email, "password", password)
}

type Account struct {
	ID       int
	Password string
}

// LogValue controls how an Account appears in logs.
func (a Account) LogValue() slog.Value { return slog.IntValue(a.ID) }

func Created(a Account) {
	slog.Info("account created", "account", a)
}
```

```text
logx/logx.go:11 sensitive-data-in-logs HIGH  Sensitive value 'password' is passed to the logger; redact or omit it to prevent credential leakage in logs.
```

`Account` has a `Password` field, but its `LogValue` method decides what is
logged, so `Created` is not reported. `zapcore.ObjectMarshaler` and
`zerolog.LogObjectMarshaler` are honored in the same way.

## Server timeouts

```go
func Serve(h http.Handler) error {
	return http.ListenAndServe(":8080", h)
}

func ServeSafe(h http.Handler) error {
	srv := &http.Server{Addr: ":8080", Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second}
	return srv.ListenAndServe()
}
```

```text
srvx/srvx.go:9 http-server-missing-timeout HIGH  http.ListenAndServe starts a server without read timeouts (Slowloris).
```

## Network calls inside a transaction

```go
func (s *Service) Pay(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", id); err != nil {
		return err
	}
	if err := s.payments.Charge(ctx, id); err != nil { // POST to the payment provider
		return err
	}
	return tx.Commit()
}
```

```text
orders/orders.go:38 tx-network-io HIGH  HTTP request (Payments.Charge -> (net/http.Client).Do) runs while the transaction opened at line 30 is held; the transaction keeps its connection and row locks until the remote call returns.
  source  orders/orders.go:30  the transaction starts here
  call    orders/orders.go:38  calls Payments.Charge
  sink    orders/orders.go:17  HTTP request: (net/http.Client).Do
```

The HTTP call is two functions away from the transaction. Charging before
`BeginTx`, or after `Commit`, is not reported.

## Excessive data exposure and mass assignment

```go
type User struct {
	ID           int64  `json:"id" db:"id"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"password_hash" db:"password_hash"`
	IsAdmin      bool   `json:"is_admin" db:"is_admin"`
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	var u User
	_ = json.NewEncoder(w).Encode(u)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_, _ = h.db.ExecContext(r.Context(), "UPDATE users SET email = $1, is_admin = $2 WHERE id = $3", u.Email, u.IsAdmin, u.ID)
}
```

```text
users/users.go:20 api-excessive-data-exposure HIGH  Type 'users.User' serialized to HTTP JSON response exposes sensitive field 'User.PasswordHash' without json:"-" tag.
users/users.go:25 api-mass-assignment HIGH  Client input is decoded directly into database model 'User' whose fields 'IsAdmin' the client can then set.
```

Responding with a type that lists only `ID` and `Email`, and decoding into a
request type with only the editable `Email`, is not reported:

```go
func (h *Handler) GetSafe(w http.ResponseWriter, r *http.Request) {
	var u User
	_ = json.NewEncoder(w).Encode(UserResponse{ID: u.ID, Email: u.Email})
}

func (h *Handler) UpdateSafe(w http.ResponseWriter, r *http.Request) {
	var req UpdateEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_, _ = h.db.ExecContext(r.Context(), "UPDATE users SET email = $1 WHERE id = $2", req.Email, currentUserID(r))
}
```

## Automatic fixes

```go
func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}
```

```bash
codex-cli scan . --fix
```

`tls-insecure-config` carries a fix, so the file is rewritten to
`InsecureSkipVerify: false`. Fixes are also included in SARIF (`fixes`) and
JSON (`fix`) reports.

## Architecture layers

With the default layout, a `handler` package belongs to the delivery layer and
a `repository` package to the repository layer. Delivery may use services and
use cases, but not repositories directly:

```go
package handler

import "example.com/shop/internal/repository"

func GetUser(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(repository.Find(1))
}
```

```text
internal/handler/handler.go:11 arch-layer-violation LOW  GetUser (layer "delivery") calls example.com/shop/internal/repository.Find in layer "repository", which it may not depend on.
```

Declare your own layers when the layout differs:

```yaml
architecture:
  layers:
    api: [internal/api]
    core: [internal/core]
    storage: [internal/storage]
  allowed_deps:
    api: [core]
    core: [storage]
    storage: []
```

## Custom taint sinks

Teach the taint engine about your own wrappers:

```yaml
taint:
  custom_sources:
    - package: example.com/shop/internal/web
      receiver: Context
      function: Param
      tags: [http]
  custom_sinks:
    - package: example.com/shop/internal/db
      function: Raw
      check_args: [0]
      category: sql-injection
  custom_sanitizers:
    - package: example.com/shop/internal/security
      function: SafeName
      categories: [path-traversal]
```

Flows from `Context.Param` into `db.Raw` are then reported as
`sql-injection`, with the same traces as the built-in sinks. A value passed
through `SafeName` is no longer reported for `path-traversal`.

## Custom YAML rule

`rules/no-panic.yaml`:

```yaml
id: acme.no-panic-in-handlers
title: Panic in request handler
category: style
severity: MEDIUM
description: Handlers must return errors instead of panicking.
match:
  pattern: "panic($X)"
suggestion: Return an error response instead.
```

```yaml
# .codexsentinel.yaml
rules:
  rule_paths: [rules]
```

Patterns are Go expressions or statements. `$X` matches any expression and
`$...` any number of arguments.

A rule with `fix:` is applied by `--fix`. The metavariables bound by the
pattern are substituted in the replacement:

```yaml
id: acme.strings-contains
title: Use strings.Contains
category: style
severity: LOW
description: strings.Index compared with -1 is clearer as strings.Contains.
match:
  pattern: "strings.Index($S, $SUB) != -1"
fix: "strings.Contains($S, $SUB)"
suggestion: Use strings.Contains.
```

```text
ISSUE [LOW] acme.strings-contains at main.go:9:5-9:36
WHY: strings.Index compared with -1 is clearer as strings.Contains.
FIX: Use strings.Contains.
PATCH: replace 9:5-9:36 with `strings.Contains("abc", "b")`
```

After `codex-cli scan . --fix` the line reads
`if strings.Contains("abc", "b") {`.

## Pull request workflow

```bash
# Fail a pull request only on new problems in the lines it changes
codex-cli scan . --diff origin/main --strict --severity medium
```

```bash
# Adopt on an existing code base: accept today's findings once...
codex-cli baseline create . --out .codexsentinel.baseline.json
```

```bash
# ...then fail only on findings that are not in the baseline
codex-cli scan . --baseline .codexsentinel.baseline.json --strict
```

```bash
# Detect dependency upgrades that add capabilities
codex-cli caps lock .
```

```bash
codex-cli caps verify .
```

## Continuous integration

### GitHub Actions

Pull request annotations and a job summary, without GitHub Advanced
Security:

```yaml
name: CodexSentinel
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: Voskan/codexsentinel@v2
        with:
          severity: medium
          diff: ${{ github.event_name == 'pull_request' && format('origin/{0}', github.base_ref) || '' }}
          forbid-new-suppressions: ${{ github.event_name == 'pull_request' }}
```

With code scanning, upload SARIF so that findings appear as alerts with
their data-flow paths:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: Voskan/codexsentinel@v2
        with:
          format: sarif
          output: results.sarif
          strict: false
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

A reviewed pull request that has to add a suppression can be approved by
setting `CODEX_ALLOW_SUPPRESSIONS=1`, for example only when a security
reviewer has applied a label:

```yaml
      - uses: Voskan/codexsentinel@v2
        env:
          CODEX_ALLOW_SUPPRESSIONS: ${{ contains(github.event.pull_request.labels.*.name, 'security-approved') && '1' || '' }}
        with:
          diff: origin/${{ github.base_ref }}
          forbid-new-suppressions: true
```

### GitLab CI

The Code Quality report is shown in merge request widgets on every tier,
including GitLab Free:

```yaml
codexsentinel:
  image: golang:1.26
  variables:
    GIT_DEPTH: 0
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
    - codex-cli scan . --format gitlab --out gl-code-quality-report.json --strict --severity medium
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

For merge requests only, add
`--diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME --forbid-new-suppressions`
and a `rules: [{if: $CI_PIPELINE_SOURCE == "merge_request_event"}]` clause.

### pre-commit

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Voskan/codexsentinel
    rev: v2.0.0
    hooks:
      - id: codexsentinel-scan   # codex-cli scan . --strict --severity high
      - id: codexsentinel-caps   # codex-cli caps verify . when go.mod, go.sum or the lock file change
```

pre-commit builds `codex-cli` from the pinned revision with the local Go
toolchain the first time the hooks run.

## OpenVEX with Trivy and Grype

Generic scanners report every known vulnerability of every dependency.
CodexSentinel knows which vulnerable functions the program can reach, and
`sbom --vex-out` writes that knowledge as OpenVEX: unreachable
vulnerabilities are `not_affected` with the justification
`vulnerable_code_not_in_execute_path`, reachable ones `affected`.

```bash
codex-cli sbom . --vex --out sbom.cdx.json --vex-out openvex.json
```

```bash
trivy sbom sbom.cdx.json --vex openvex.json
```

```bash
grype sbom:sbom.cdx.json --vex openvex.json
```

Both scanners then hide the vulnerabilities the VEX document marks
`not_affected`. Publish both files with the release so that consumers can do
the same.
