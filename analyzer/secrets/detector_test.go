package secrets

import (
	"go/parser"
	"go/token"
	"math"
	"strings"
	"testing"
)

func scanSource(t *testing.T, name, src string) []Finding {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ScanFile(fset, file)
}

// Synthetic credentials are assembled at run time so that the source of this
// test does not itself contain anything that looks like a live secret.
var (
	awsKey    = "AKIA" + "Z7QH3K2M9XB4WT6R"
	githubPAT = "ghp_" + strings.Repeat("aB3dE5gH7j", 4)
	pemHeader = "-----BEGIN RSA " + "PRIVATE KEY-----"
)

func TestDetectorPatterns(t *testing.T) {
	cases := []struct {
		name string
		text string
		kind string
	}{
		{"aws", "key := \"" + awsKey + "\"", "AWS access key"},
		{"github", "token: " + githubPAT, "GitHub token"},
		{"pem", pemHeader + "\nMIIEow...", "private key"},
		{"dsn", "postgres://app:Xk9#mP2qLw@db.prod.internal:5432/app", "connection string with password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := ScanText(tc.text)
			if len(found) != 1 || found[0].Kind != tc.kind {
				t.Fatalf("want one %q finding, got %+v", tc.kind, found)
			}
			if found[0].Level != LevelPattern || found[0].Confidence != 0.98 {
				t.Fatalf("unexpected level/confidence: %+v", found[0])
			}
			if tc.kind != "private key" && strings.Contains(found[0].Value, tc.text[len(tc.text)-6:]) {
				t.Fatalf("value not redacted: %q", found[0].Value)
			}
		})
	}
}

func TestDetectorPatternFiltering(t *testing.T) {
	for _, text := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://user:pass@localhost:5432/db",
		"postgres://user:${DB_PASSWORD}@db.prod.internal/app",
		"mysql://root:<password>@10.0.0.1/app",
		"redis://default:secret@example.com:6379",
		"ghp_short",
	} {
		if found := ScanText(text); len(found) != 0 {
			t.Errorf("%q: unexpected findings %+v", text, found)
		}
	}
}

func TestDetectorContextLevel(t *testing.T) {
	src := `package app

const signingKey = "q8Z!vR2#kLp9@Wm4$Tx7"

var config = map[string]string{
	"api_key": "4fG7hK2mN9pQ3rS8tV1w",
}

type DB struct{ Password string }

func setup() {
	password := "Tr0ub4dor&3x"
	_ = password
	_ = DB{Password: "s3cureP4ssw0rd!"}
}
`
	found := scanSource(t, "app.go", src)
	got := map[string]bool{}
	for _, f := range found {
		if f.Level != LevelContext || f.Confidence != 0.8 {
			t.Errorf("unexpected finding %+v", f)
		}
		got[f.Name] = true
	}
	for _, name := range []string{"signingKey", "api_key", "password", "Password"} {
		if !got[name] {
			t.Errorf("missing finding for %s; got %+v", name, found)
		}
	}
	if len(found) != 4 {
		t.Errorf("want 4 findings, got %d: %+v", len(found), found)
	}
}

func TestDetectorNoFalsePositives(t *testing.T) {
	src := `package app

import "errors"

const HeaderAuthorization = "Authorization"
const AuthHeader = "Authorization"
const EnvSecretKey = "APP_SECRET_KEY"
const PasswordEnv = "DB_PASSWORD"
const SessionCookieName = "session_token_v2"
const JWTKeyName = "kid-current-rotation"
const SecretPath = "/etc/app/secret.key"

var ErrInvalidPassword = errors.New("invalid password: must contain 12 characters")

const passwordQuery = "SELECT id FROM users WHERE email = $1 AND password_hash = $2"

const page = "<html><body><input type=\"password\" name=\"password\"></body></html>"

var defaults = struct{ Password, APIKey string }{Password: "changeme", APIKey: "your-api-key-here"}

func f() {
	secret := ""
	apiKey := "${API_KEY}"
	token := "Bearer "
	_, _, _ = secret, apiKey, token
}
`
	if found := scanSource(t, "app.go", src); len(found) != 0 {
		t.Fatalf("unexpected findings: %+v", found)
	}
}

func TestDetectorSkipsContextInTests(t *testing.T) {
	src := "package app\n\nconst apiKey = \"4fG7hK2mN9pQ3rS8tV1w\"\n"
	if found := scanSource(t, "app_test.go", src); len(found) != 0 {
		t.Fatalf("unexpected findings in test file: %+v", found)
	}
}

func TestEntropyCountsRunes(t *testing.T) {
	if got := Entropy("ab"); math.Abs(got-1) > 1e-9 {
		t.Fatalf("Entropy(ab) = %v", got)
	}
	if got := Entropy("пр"); math.Abs(got-1) > 1e-9 {
		t.Fatalf("Entropy of two distinct runes = %v, want 1", got)
	}
	if got := Entropy("aaaa"); got != 0 {
		t.Fatalf("Entropy(aaaa) = %v", got)
	}
}

func TestSecretName(t *testing.T) {
	for name, want := range map[string]string{
		"apiKey": "API key", "API_KEY": "API key", "privateKey": "private key", "signingKey": "signing key",
		"authToken": "auth token", "dbPassword": "password", "clientSecret": "secret",
		"AuthHeader": "", "PasswordEnv": "", "KeyName": "", "SecretPath": "", "TokenURL": "", "SessionCookieName": "",
		"EnvSecretKey": "", "keyboard": "", "monkey": "",
	} {
		if got, _ := SecretName(name); got != want {
			t.Errorf("SecretName(%q) = %q, want %q", name, got, want)
		}
	}
}
