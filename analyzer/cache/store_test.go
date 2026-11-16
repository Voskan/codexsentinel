package cache

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "nested"))
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("ab", 32)
	var got []string
	if c.Get(key, &got) {
		t.Fatal("hit on empty cache")
	}
	if err := c.Put(key, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	if !c.Get(key, &got) || len(got) != 2 || got[1] != "y" {
		t.Fatalf("Get = %v", got)
	}
	if s := c.Stats(); s.Hits != 1 || s.Misses != 1 || s.Writes != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if _, err := os.Stat(filepath.Join(c.Dir(), "ab", key+entrySuffix)); err != nil {
		t.Fatalf("entry not sharded: %v", err)
	}
}

func TestCorruptEntryIsAMiss(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("cd", 32)
	path, _ := c.path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	var v any
	if c.Get(key, &v) {
		t.Fatal("corrupt entry returned")
	}
}

func TestInvalidKeysAreRejected(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "ab", "../../etc", "a/b/c"} {
		if err := c.Put(key, 1); err == nil {
			t.Errorf("Put(%q) accepted", key)
		}
	}
}

func TestConcurrentWritersAndReaders(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("ef", 32)
	payload := strings.Repeat("value ", 10000)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := c.Put(key, payload); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			var got string
			if c.Get(key, &got) && got != payload {
				t.Error("read a partial entry")
			}
		}()
	}
	wg.Wait()
}

func TestUsageAndCleanOnlyTouchEntries(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{strings.Repeat("01", 32), strings.Repeat("02", 32)} {
		if err := c.Put(key, key); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(dir, "README")
	if err := os.WriteFile(keep, []byte("not an entry"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, size, err := Usage(dir); err != nil || n != 2 || size == 0 {
		t.Fatalf("Usage = %d, %d, %v", n, size, err)
	}
	if removed, err := Clean(dir); err != nil || removed != 2 {
		t.Fatalf("Clean = %d, %v", removed, err)
	}
	if n, _, _ := Usage(dir); n != 0 {
		t.Fatalf("%d entries left", n)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("Clean removed a file that is not a cache entry")
	}
	if _, err := os.Stat(filepath.Join(dir, "01")); !os.IsNotExist(err) {
		t.Fatal("empty shard directory kept")
	}
	if n, _, err := Usage(filepath.Join(dir, "missing")); err != nil || n != 0 {
		t.Fatalf("missing directory: %d, %v", n, err)
	}
}

func TestResolveDir(t *testing.T) {
	t.Setenv(EnvDir, "")
	explicit := t.TempDir()
	if got, _ := ResolveDir(explicit); got != explicit {
		t.Fatalf("ResolveDir(%q) = %q", explicit, got)
	}
	env := t.TempDir()
	t.Setenv(EnvDir, env)
	if got, _ := ResolveDir(""); got != env {
		t.Fatalf("env override = %q, want %q", got, env)
	}
	t.Setenv(EnvDir, "")
	if got, err := ResolveDir(""); err != nil || !strings.HasSuffix(got, filepath.Join("codexsentinel", "cache-v1")) {
		t.Fatalf("default = %q, %v", got, err)
	}
}
