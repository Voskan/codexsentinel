package critsec_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/critsec"
	"github.com/Voskan/codexsentinel/analyzer/result"
	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func analyze(t *testing.T, files map[string]string) []result.Issue {
	t.Helper()
	fx := testutil.LoadFixture(t, files, nil)
	bundle, err := codessa.BuildFromWorkspace(fx.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	issues := critsec.Analyze(fx.Workspace, bundle, nil)
	for i := range issues {
		issues[i].Location.File = rel(fx.Dir, issues[i].Location.File)
		for j := range issues[i].Trace {
			issues[i].Trace[j].Location.File = rel(fx.Dir, issues[i].Trace[j].Location.File)
		}
	}
	testutil.CheckExpectations(t, files, issues)
	return issues
}

func rel(dir, file string) string {
	if r, err := filepath.Rel(dir, file); err == nil {
		return filepath.ToSlash(r)
	}
	return file
}

const paymentSrc = `package payment

import (
	"context"
	"net/http"
	"strings"
)

type Client struct {
	HTTP *http.Client
	URL  string
}

func (c *Client) Charge(ctx context.Context, amount string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, strings.NewReader(amount))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
`

func TestTransactionAroundRemoteCall(t *testing.T) {
	issues := analyze(t, map[string]string{
		"payment/payment.go": paymentSrc,
		"orders/orders.go": `package orders

import (
	"context"
	"database/sql"
	"net/http"

	"example.com/fixture/payment"
)

type Charger interface {
	Charge(ctx context.Context, amount string) error
}

type OrderService struct {
	DB       *sql.DB
	Payments Charger
}

func (s *OrderService) PlaceOrder(ctx context.Context, amount string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO orders(amount) VALUES ($1)", amount); err != nil {
		return err
	}
	if err := s.Payments.Charge(ctx, amount); err != nil { // want "tx-network-io"
		return err
	}
	return tx.Commit()
}

func (s *OrderService) ChargeAfterCommit(ctx context.Context, amount string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO orders(amount) VALUES ($1)", amount); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Payments.Charge(ctx, amount)
}

func (s *OrderService) ChargeBeforeBegin(ctx context.Context, amount string) error {
	if err := s.Payments.Charge(ctx, amount); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return tx.Commit()
}

func NewOrderService(db *sql.DB) *OrderService {
	return &OrderService{DB: db, Payments: &payment.Client{HTTP: http.DefaultClient}}
}
`})
	if len(issues) != 1 {
		t.Fatalf("want one finding, got %d", len(issues))
	}
	var steps []string
	for _, s := range issues[0].Trace {
		steps = append(steps, s.Kind+":"+s.Message)
	}
	got := strings.Join(steps, " | ")
	for _, want := range []string{"source:the transaction starts here", "call:calls Client.Charge", "sink:HTTP request: (net/http.Client).Do"} {
		if !strings.Contains(got, want) {
			t.Fatalf("trace %q lacks %q", got, want)
		}
	}
	if issues[0].Category != "reliability" || issues[0].Severity != result.SeverityHigh {
		t.Fatalf("unexpected classification: %+v", issues[0])
	}
}

func TestGormTransactionCallback(t *testing.T) {
	analyze(t, map[string]string{
		"go.mod":            "module example.com/fixture\n\ngo 1.24\n\nrequire gorm.io/gorm v1.25.0\n\nreplace gorm.io/gorm => ./stubs/gorm\n",
		"stubs/gorm/go.mod": "module gorm.io/gorm\n\ngo 1.24\n",
		"stubs/gorm/gorm.go": `package gorm

type DB struct{}

func (db *DB) Transaction(fc func(tx *DB) error) error { return fc(db) }
func (db *DB) Create(v any) *DB                         { return db }
`,
		"app/app.go": `package app

import (
	"net/http"
	"time"

	"gorm.io/gorm"
)

func Save(db *gorm.DB, v any) error {
	return db.Transaction(func(tx *gorm.DB) error {
		tx.Create(v)
		resp, err := http.Get("https://audit.example.com/log") // want "tx-network-io"
		if err != nil {
			return err
		}
		time.Sleep(time.Second) // want "tx-network-io:sleep"
		return resp.Body.Close()
	})
}

func SaveQuietly(db *gorm.DB, v any) error {
	return db.Transaction(func(tx *gorm.DB) error {
		tx.Create(v)
		go http.Get("https://audit.example.com/log")
		return nil
	})
}
`})
}

func TestMutexAroundRemoteCall(t *testing.T) {
	analyze(t, map[string]string{"cache/cache.go": `package cache

import (
	"net/http"
	"sync"
)

type Cache struct {
	mu    sync.Mutex
	items map[string]string
}

func fetchRemote(key string) string {
	resp, err := http.Get("https://config.example.com/" + key)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return key
}

func (c *Cache) Locked(key string) string {
	c.mu.Lock()
	v := fetchRemote(key) // want "lock-blocking-io"
	c.mu.Unlock()
	return v
}

func (c *Cache) Deferred(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fetchRemote(key) // want "lock-blocking-io"
}

func (c *Cache) Unlocked(key string) string {
	c.mu.Lock()
	v, ok := c.items[key]
	c.mu.Unlock()
	if ok {
		return v
	}
	return fetchRemote(key)
}

var global sync.RWMutex

func ReadLocked(key string) string {
	global.RLock()
	defer global.RUnlock()
	return fetchRemote(key) // want "lock-blocking-io"
}
`})
}
