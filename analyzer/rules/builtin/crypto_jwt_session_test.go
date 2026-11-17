package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/testutil"
)

const jwtStub = `package jwt

type SigningMethod interface{ Alg() string }

type signingMethodNone struct{}

func (signingMethodNone) Alg() string { return "none" }

type SigningMethodHMAC struct{ Name string }

func (m *SigningMethodHMAC) Alg() string { return m.Name }

var (
	SigningMethodNone  SigningMethod = signingMethodNone{}
	SigningMethodHS256               = &SigningMethodHMAC{Name: "HS256"}
)

const UnsafeAllowNoneSignatureType = "none signing method allowed"

type Claims interface{}

type MapClaims map[string]any

type Token struct {
	Method SigningMethod
	Header map[string]any
	Claims Claims
	Valid  bool
}

func (t *Token) SignedString(key any) (string, error) { return "", nil }

func NewWithClaims(m SigningMethod, c Claims) *Token { return &Token{Method: m, Claims: c} }

type Keyfunc func(*Token) (any, error)

type ParserOption func(*Parser)

func WithValidMethods(methods []string) ParserOption { return func(*Parser) {} }

type Parser struct{}

func NewParser(opts ...ParserOption) *Parser { return &Parser{} }

func (p *Parser) Parse(s string, k Keyfunc) (*Token, error) { return nil, nil }

func (p *Parser) ParseUnverified(s string, c Claims) (*Token, []string, error) { return nil, nil, nil }

func Parse(s string, k Keyfunc, opts ...ParserOption) (*Token, error) { return nil, nil }

func ParseWithClaims(s string, c Claims, k Keyfunc, opts ...ParserOption) (*Token, error) { return nil, nil }
`

func jwtFiles(app string) map[string]string {
	return map[string]string{
		"go.mod":           "module example.com/fixture\n\ngo 1.24\n\nrequire github.com/golang-jwt/jwt/v5 v5.0.0\n\nreplace github.com/golang-jwt/jwt/v5 => ./stubs/jwt\n",
		"stubs/jwt/go.mod": "module github.com/golang-jwt/jwt/v5\n\ngo 1.24\n",
		"stubs/jwt/jwt.go": jwtStub,
		"app/app.go":       app,
	}
}

func registerCryptoJWTSession(ctx *analyzer.AnalyzerContext) {
	RegisterJWTSecurityRule(ctx)
	RegisterCryptoWeakRule(ctx)
	RegisterSessionManagementRule(ctx)
}

func TestCryptoJWTSessionJWT(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, jwtFiles(`package app

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type Message struct {
	Type   string
	Header string
	Token  int
}

var signingKey = []byte("short-secret")

func sign() (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{}) // want "jwt-alg-none"
	_, _ = tok.SignedString(jwt.UnsafeAllowNoneSignatureType) // want "jwt-alg-none"
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{}).SignedString(signingKey) // want "jwt-weak-secret"
}

func inspect(raw string) {
	p := jwt.NewParser()
	p.ParseUnverified(raw, jwt.MapClaims{}) // want "jwt-unverified-parse"
}

func keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("unexpected method")
	}
	return []byte("k"), nil
}

func verify(raw string, key []byte) {
	jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil }) // want "jwt-missing-alg-check"
	jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}))
	jwt.ParseWithClaims(raw, jwt.MapClaims{}, keyFunc)
	jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Header["alg"] != "RS256" {
			return nil, errors.New("bad alg")
		}
		return key, nil
	})
	jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})).Parse(raw, func(t *jwt.Token) (any, error) { return key, nil })
	_ = Message{Type: "a", Header: "b", Token: 1}
}

func verifyBoth(raw string, key []byte) {
	p := jwt.NewParser()
	p.ParseUnverified(raw, jwt.MapClaims{})
	jwt.Parse(raw, keyFunc)
}
`), registerCryptoJWTSession)
}

func TestCryptoJWTSessionCrypto(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"io"
	mrand "math/rand"
	randv2 "math/rand/v2"
	"strconv"
)

func hashes(b []byte) {
	md5.Sum(b) // want "crypto-weak-hash"
	sha256.Sum256(b)
	des.NewCipher(b) // want "crypto-weak-cipher"
}

func keys() {
	rsa.GenerateKey(rand.Reader, 1024) // want "crypto-weak-rsa"
	rsa.GenerateKey(rand.Reader, 2048)
}

func generateAPIToken() string {
	return strconv.FormatUint(randv2.Uint64(), 36) // want "crypto-weak-rand"
}

func shuffle(items []int) {
	mrand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	jitter := mrand.Intn(100)
	_ = jitter
	sessionID := mrand.Int63() // want "crypto-weak-rand"
	_ = sessionID
}

func configs() []*tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg.InsecureSkipVerify = true // want "tls-insecure-config"
	return []*tls.Config{
		{InsecureSkipVerify: true}, // want "tls-insecure-config"
		{MinVersion: tls.VersionTLS10}, // want "tls-insecure-config"
		{MinVersion: tls.VersionTLS12},
		cfg,
	}
}

func seal(key, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	out := gcm.Seal(nil, nonce, plaintext, nil) // want "crypto-weak-cipher"
	fresh := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, fresh); err != nil {
		return nil
	}
	return append(out, gcm.Seal(nil, fresh, plaintext, nil)...)
}
`}, registerCryptoJWTSession)
}

func TestCryptoJWTSessionCookies(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app.go": `package app

import "net/http"

func login(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: v}) // want "cookie-missing-httponly" "cookie-missing-secure"
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: v, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
	http.SetCookie(w, &http.Cookie{Name: "prefs", Value: v, SameSite: http.SameSiteNoneMode}) // want "cookie-insecure-samesite"
	c := &http.Cookie{Name: "auth_token", Value: v}
	c.HttpOnly = true
	c.Secure = true
	http.SetCookie(w, c)
}
`}, registerCryptoJWTSession)
}
