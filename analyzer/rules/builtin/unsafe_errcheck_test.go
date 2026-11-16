package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func TestUnsafeErrcheckIgnoredErrors(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":                   "module example.com/fixture\n\ngo 1.24\n\nrequire golang.org/x/crypto v1.0.0\n\nreplace golang.org/x/crypto => ./stubs/crypto\n",
		"stubs/crypto/go.mod":      "module golang.org/x/crypto\n\ngo 1.24\n",
		"stubs/crypto/bcrypt/b.go": "package bcrypt\n\nfunc CompareHashAndPassword(hash, password []byte) error { return nil }\n",
		"app/app.go": `package app

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/bcrypt"
)

func newKey() []byte {
	key := make([]byte, 32)
	rand.Read(key) // want "security-err-ignored"
	return key
}

func newNonce() []byte {
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce) // want "security-err-ignored"
	return nonce
}

func readerKey() []byte {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key) // want "security-err-ignored"
	rand.Reader.Read(key)         // want "security-err-ignored"
	return key
}

func checkedKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func login(hash, password []byte) bool {
	bcrypt.CompareHashAndPassword(hash, password) // want "security-err-ignored"
	return true
}

func loginChecked(hash, password []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, password) == nil
}

func secure(path string, conn *tls.Conn, cert *x509.Certificate) {
	os.Chmod(path, 0o600)                       // want "security-err-ignored"
	_ = os.Chown(path, 0, 0)                    // want "security-err-ignored"
	conn.Handshake()                            // want "security-err-ignored"
	_, _ = cert.Verify(x509.VerifyOptions{})    // want "security-err-ignored"
	syscall.Setuid(1000)                        // want "security-err-ignored"
	fmt.Println("ok")
	f, _ := os.Open(path)
	f.Close()
}

func secureChecked(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return syscall.Setgid(1000)
}

func count(db *sql.DB) int {
	rows, err := db.Query("SELECT 1") // want "security-err-ignored:rows.Err"
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n
}

func countIgnored(db *sql.DB) int {
	rows, err := db.Query("SELECT 1")
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	rows.Err() // want "security-err-ignored"
	return n
}

func countChecked(db *sql.DB) (int, error) {
	rows, err := db.Query("SELECT 1")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}
`,
	}
	issues := testutil.RunRulesOnFiles(t, files, RegisterUnsafeErrcheckRules)
	critical := 0
	for _, is := range issues {
		if is.Severity == result.SeverityCritical {
			critical++
		}
	}
	if critical != 5 {
		t.Errorf("critical findings = %d, want 5 (random reads and bcrypt)", critical)
	}
}

func TestUnsafeErrcheckMemory(t *testing.T) {
	t.Parallel()
	issues := testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"fmt"
	"reflect"
	"unsafe"
)

type header struct{ a, b int64 }

func roundTrip(h *header) *int64 {
	addr := uintptr(unsafe.Pointer(h)) // want "unsafe-memory-manipulation"
	return (*int64)(unsafe.Pointer(addr + 8))
}

func bytesToString(b []byte) string {
	var s string
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s)) // want "unsafe-memory-manipulation"
	sh.Data = uintptr(unsafe.Pointer(&b[0]))
	sh.Len = len(b)
	return s
}

func fromLength(p *byte, n int) []byte {
	return unsafe.Slice(p, n) // want "unsafe-memory-manipulation"
}

func secondField(buf []byte) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(&buf[0]), 4)
}

func aligned(p *header) bool {
	addr := uintptr(unsafe.Pointer(p))
	fmt.Println(addr)
	return addr%8 == 0
}

func view(b []byte) []byte {
	return unsafe.Slice(&b[0], len(b))
}

func bounded(p *byte, n, size int) []byte {
	if n > size {
		n = size
	}
	return unsafe.Slice(p, n)
}

func str(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func syscallArg(p *header) uintptr {
	return uintptr(unsafe.Pointer(p))
}
`), RegisterUnsafeErrcheckRules)
	for _, is := range issues {
		if is.Severity == result.SeverityCritical {
			t.Errorf("%s at line %d: unexpected critical severity", is.ID, is.Location.Line)
		}
	}
}
