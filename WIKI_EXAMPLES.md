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
- [CSRF and http.CrossOriginProtection](#csrf-and-httpcrossoriginprotection)
- [Secrets in logs](#secrets-in-logs)
- [Server timeouts](#server-timeouts)
- [Automatic fixes](#automatic-fixes)
- [Architecture layers](#architecture-layers)
- [Custom taint sinks](#custom-taint-sinks)
- [Custom YAML rule](#custom-yaml-rule)
- [Pull request workflow](#pull-request-workflow)
- [GitLab CI](#gitlab-ci)

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
`$...` any number of arguments. Add `fix:` with a replacement template to
make the rule fixable with `--fix`.

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

## GitLab CI

```yaml
codexsentinel:
  image: golang:1.24
  variables:
    GIT_DEPTH: 0
  script:
    - go install github.com/Voskan/codexsentinel/cmd/codex-cli@latest
    - codex-cli scan . --strict --severity high --format sarif --out gl-codexsentinel.sarif
  artifacts:
    when: always
    paths:
      - gl-codexsentinel.sarif
```
