package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func TestPIILoggingStructs(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"login.go": `package app

import (
	"log"
	"log/slog"
)

type LoginReq struct {
	Email    string
	Password string
}

type SafeLoginReq struct {
	Email    string
	Password string
}

func (SafeLoginReq) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type Order struct {
	ID     int
	Status string
}

type Account struct {
	Name  string
	Login LoginReq
}

type APIResponse struct {
	AccessToken string ` + "`json:\"-\"`" + `
	Scope       string
}

func handle(req LoginReq, safe SafeLoginReq, o Order, acc *Account, resp APIResponse) {
	slog.Info("login", "req", req) // want "sensitive-data-in-logs:Struct 'LoginReq' passed to logger exposes sensitive field 'Password'. Implement slog.LogValuer (or omit the struct) to prevent credential leakage in logs."
	slog.Info("login", "req", safe)
	slog.Info("order", "o", o)
	slog.Info("account", slog.Any("acc", acc)) // want "sensitive-data-in-logs:Struct 'Account' passed to logger exposes sensitive field 'Login.Password'"
	slog.Info("token", "resp", resp)
	log.Printf("login %+v", &req) // want "sensitive-data-in-logs:Implement fmt.Stringer"
}
`}, RegisterLoggingMonitoringRule)
}

func TestPIILoggingValues(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"values.go": `package app

import (
	"context"
	"log"
	"log/slog"
	"net/http"
)

func mask(s string) string { return "****" }

func values(ctx context.Context, r *http.Request, pwd, apiToken, user string, logger *slog.Logger) {
	slog.Info("auth", "password", pwd) // want "sensitive-data-in-logs:Sensitive value 'password'"
	log.Printf("token=%s", apiToken) // want "sensitive-data-in-logs:Sensitive value"
	logger.InfoContext(ctx, "call", "auth", r.Header.Get("Authorization")) // want "sensitive-data-in-logs:Sensitive value 'Authorization'"
	slog.Info("auth", "password", mask(pwd))
	slog.Info("auth", "password_set", pwd != "")
	slog.Info("auth", "password", "***")
	slog.Info("user", "name", user, "password_len", len(pwd))
	log.Printf("user=%s attempts=%d", user, 3)
	log.Println("failed login for", user)
}
`}, RegisterLoggingMonitoringRule)
}

func TestPIILoggingZerolog(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{
		"go.mod":               "module example.com/fixture\n\ngo 1.24\n\nrequire github.com/rs/zerolog v1.0.0\n\nreplace github.com/rs/zerolog => ./stubs/zerolog\n",
		"stubs/zerolog/go.mod": "module github.com/rs/zerolog\n\ngo 1.24\n",
		"stubs/zerolog/log.go": `package zerolog

type Event struct{}
type Logger struct{}

func (l *Logger) Info() *Event                             { return &Event{} }
func (e *Event) Str(key, val string) *Event                { return e }
func (e *Event) Interface(key string, v interface{}) *Event { return e }
func (e *Event) Msg(msg string)                            {}
func (e *Event) Msgf(format string, v ...interface{})      {}
`,
		"app.go": `package app

import "github.com/rs/zerolog"

type Card struct {
	Holder     string
	CardNumber string ` + "`json:\"card_number\"`" + `
}

func pay(l *zerolog.Logger, c Card, cvv string) {
	l.Info().Interface("card", c).Msg("payment") // want "sensitive-data-in-logs:Implement zerolog.LogObjectMarshaler"
	l.Info().Str("cvv", cvv).Msg("payment") // want "sensitive-data-in-logs:Sensitive value 'cvv'"
	l.Info().Str("holder", c.Holder).Msgf("card %s", c.CardNumber) // want "sensitive-data-in-logs:Sensitive value 'CardNumber'"
}
`,
	}, RegisterLoggingMonitoringRule)
}

func TestHardcodedSecretRule(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"cfg.go": `package app

const HeaderAuthorization = "Authorization"
const EnvSecretKey = "APP_SECRET_KEY"

const signingKey = "q8Z!vR2#kLp9@Wm4$Tx7" // want "hardcoded-secret:hardcoded signing key"

var dsn = "postgres://svc:Xk9qmP2qLw@db.prod.internal:5432/app" // want "hardcoded-secret:Hardcoded connection string with password"
`}, RegisterHardcodedSecretRule)
}
