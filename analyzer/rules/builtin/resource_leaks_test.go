package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func leakFiles(app string) map[string]string {
	return map[string]string{
		"go.mod":     "module example.com/fixture\n\ngo 1.24\n",
		"app/app.go": app,
	}
}

func TestSQLTxMissingRollback(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"context"
	"database/sql"
	"errors"
)

func transfer(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil) // want "sql-tx-missing-rollback"
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE accounts SET balance = balance - 1"); err != nil {
		return err
	}
	return tx.Commit()
}

func reusedErr(db *sql.DB) error {
	tx, err := db.Begin() // want "sql-tx-missing-rollback"
	if err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM sessions"); err != nil {
		return err
	}
	return tx.Commit()
}

func deferred(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE a"); err != nil {
		return err
	}
	return tx.Commit()
}

func deferredClosure(db *sql.DB) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	_, err = tx.Exec("UPDATE a")
	return err
}

func explicit(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE a"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func handedOver(db *sql.DB) (*sql.Tx, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("no tx")
	}
	return tx, nil
}

func passed(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	return finish(tx)
}

func finish(tx *sql.Tx) error { return tx.Commit() }
`), RegisterResourceLeakRules)
}

func TestHTTPBodyUnclosed(t *testing.T) {
	t.Parallel()
	issues := testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"encoding/json"
	"io"
	"net/http"
)

func status(url string) (int, error) {
	resp, err := http.Get(url) // want "http-body-unclosed"
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

func readAll(c *http.Client, req *http.Request) ([]byte, error) {
	resp, err := c.Do(req) // want "http-body-unclosed"
	if err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}

func ping(url string) error {
	_, err := http.Head(url) // want "http-body-unclosed"
	return err
}

func closed(url string, v any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func closedInClosure(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return nil
}

func returned(url string) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func delegated(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	return consume(resp)
}

func consume(resp *http.Response) error { return resp.Body.Close() }
`), RegisterResourceLeakRules)
	for _, is := range issues {
		if is.Category != "reliability" {
			t.Errorf("%s: category %q, want reliability", is.ID, is.Category)
		}
	}
}

func TestSQLRowsUnclosed(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"context"
	"database/sql"
)

func names(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM users") // want "sql-rows-unclosed"
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func closed(ctx context.Context, db *sql.DB) (int, error) {
	rows, err := db.QueryContext(ctx, "SELECT 1")
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

func returned(tx *sql.Tx) (*sql.Rows, error) {
	rows, err := tx.Query("SELECT 1")
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func single(db *sql.DB) (string, error) {
	var s string
	err := db.QueryRow("SELECT 1").Scan(&s)
	return s, err
}
`), RegisterResourceLeakRules)
}

func TestDeferInLoop(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"os"
	"sync"
)

func process(paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close() // want "defer-in-loop"
	}
	return nil
}

func nested(n int) {
	for i := 0; i < n; i++ {
		func() {
			for {
				defer println(i) // want "defer-in-loop"
				break
			}
		}()
	}
}

func perIteration(paths []string) error {
	for _, p := range paths {
		if err := func() error {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			return nil
		}(); err != nil {
			return err
		}
	}
	return nil
}

func workers(n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
		}()
	}
	wg.Wait()
}

func outside() {
	defer println("done")
	for i := 0; i < 3; i++ {
		println(i)
	}
}
`), RegisterResourceLeakRules)
}

func TestGoroutineChannelLeak(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, leakFiles(`package app

import (
	"context"
	"errors"
	"net/http"
)

func work() error { return nil }

func withTimeout(ctx context.Context) error {
	done := make(chan error)
	go func() {
		done <- work() // want "goroutine-channel-leak"
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func earlyReturn(r *http.Request) error {
	ch := make(chan int)
	go func() {
		ch <- 1 // want "goroutine-channel-leak"
	}()
	if r.URL.Path == "" {
		return errors.New("empty path")
	}
	<-ch
	return nil
}

func buffered(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- work()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func selectSend(ctx context.Context) error {
	done := make(chan error)
	go func() {
		select {
		case done <- work():
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func alwaysReceives(ctx context.Context) error {
	done := make(chan error)
	go func() {
		done <- work()
	}()
	return <-done
}

func noCancellation() error {
	done := make(chan error)
	go func() {
		done <- work()
	}()
	return <-done
}
`), RegisterResourceLeakRules)
}

func TestResourceLeakRulesAreReliability(t *testing.T) {
	t.Parallel()
	for _, meta := range []ruleMeta{txRollbackMeta, bodyUnclosedMeta, rowsUnclosedMeta, deferLoopMeta, goroutineLeakMeta} {
		if meta.category() != "reliability" {
			t.Errorf("%s: category %q", meta.ID, meta.category())
		}
		if meta.Severity != result.SeverityHigh && meta.Severity != result.SeverityMedium {
			t.Errorf("%s: unexpected severity %s", meta.ID, meta.Severity)
		}
	}
}
