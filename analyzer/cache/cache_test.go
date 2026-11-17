package cache_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/cache"
	"github.com/Voskan/codexsentinel/v2/analyzer/engine"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/config"
)

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.test/app\n\ngo 1.24\n"
	for name, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const modelSrc = "package model\n\ntype User struct {\n\tName string\n}\n"

const handlerSrc = `package handler

import (
	"database/sql"
	"log/slog"

	"example.test/app/model"
)

func Log(u model.User) {
	slog.Info("user", "user", u)
}

func Find(db *sql.DB, name string) {
	_, _ = db.Query("SELECT id FROM users WHERE name = '" + name + "'")
}
`

func scan(t *testing.T, dir string, cfg config.Config, store *cache.Cache) ([]result.Issue, cache.Stats) {
	t.Helper()
	before := store.Stats()
	issues, err := engine.RunWithOptions(context.Background(), dir, &cfg, engine.Options{Cache: store})
	if err != nil {
		t.Fatal(err)
	}
	after := store.Stats()
	return issues, cache.Stats{Hits: after.Hits - before.Hits, Misses: after.Misses - before.Misses, Writes: after.Writes - before.Writes}
}

func openCache(t *testing.T) *cache.Cache {
	t.Helper()
	store, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func hasRule(issues []result.Issue, id string) bool {
	for _, issue := range issues {
		if issue.ID == id {
			return true
		}
	}
	return false
}

func TestSecondRunIsServedFromCache(t *testing.T) {
	dir := writeModule(t, map[string]string{"model/model.go": modelSrc, "handler/handler.go": handlerSrc})
	store := openCache(t)
	cfg := config.NewDefaultConfig()
	first, stats := scan(t, dir, cfg, store)
	if stats.Misses != 2 || stats.Hits != 0 || stats.Writes != 2 {
		t.Fatalf("first run stats = %+v, want 2 misses and 2 writes", stats)
	}
	if !hasRule(first, "sql-injection") {
		t.Fatalf("expected a package rule finding, got %+v", first)
	}
	second, stats := scan(t, dir, cfg, store)
	if stats.Hits != 2 || stats.Misses != 0 {
		t.Fatalf("second run stats = %+v, want 2 hits", stats)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("cached findings differ:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	entries, size, err := cache.Usage(store.Dir())
	if err != nil || entries != 2 || size == 0 {
		t.Fatalf("Usage = %d, %d, %v", entries, size, err)
	}
}

func TestEditAndConfigChangeInvalidate(t *testing.T) {
	dir := writeModule(t, map[string]string{"model/model.go": modelSrc, "handler/handler.go": handlerSrc})
	store := openCache(t)
	cfg := config.NewDefaultConfig()
	scan(t, dir, cfg, store)

	path := filepath.Join(dir, "handler", "handler.go")
	if err := os.WriteFile(path, []byte(strings.Replace(handlerSrc, "SELECT id", "SELECT ID", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stats := scan(t, dir, cfg, store); stats.Misses != 1 || stats.Hits != 1 {
		t.Fatalf("after editing one file: %+v, want 1 miss and 1 hit", stats)
	}

	cfg.Rules.Disabled = []string{"sql-injection"}
	issues, stats := scan(t, dir, cfg, store)
	if stats.Misses != 2 {
		t.Fatalf("after changing the configuration: %+v, want 2 misses", stats)
	}
	if hasRule(issues, "sql-injection") {
		t.Fatal("disabled rule reported from the cache")
	}
}

func TestImportedTypeChangeInvalidatesImporter(t *testing.T) {
	dir := writeModule(t, map[string]string{"model/model.go": modelSrc, "handler/handler.go": handlerSrc})
	store := openCache(t)
	cfg := config.NewDefaultConfig()
	issues, _ := scan(t, dir, cfg, store)
	if hasRule(issues, "sensitive-data-in-logs") {
		t.Fatalf("unexpected finding before the change: %+v", issues)
	}

	withPassword := strings.Replace(modelSrc, "\tName string\n", "\tName     string\n\tPassword string\n", 1)
	if err := os.WriteFile(filepath.Join(dir, "model", "model.go"), []byte(withPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	issues, stats := scan(t, dir, cfg, store)
	if stats.Misses != 2 {
		t.Fatalf("stats = %+v, want both packages re-analyzed", stats)
	}
	if !hasRule(issues, "sensitive-data-in-logs") {
		t.Fatalf("logging a User with a Password field is not reported: %+v", issues)
	}
}

func TestBodyOnlyChangeKeepsImporterKey(t *testing.T) {
	model := modelSrc + "\nfunc (u User) Display() string { return u.Name }\n"
	dir := writeModule(t, map[string]string{"model/model.go": model, "handler/handler.go": handlerSrc})
	store := openCache(t)
	cfg := config.NewDefaultConfig()
	scan(t, dir, cfg, store)
	edited := strings.Replace(model, "return u.Name", `return "user " + u.Name`, 1)
	if err := os.WriteFile(filepath.Join(dir, "model", "model.go"), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stats := scan(t, dir, cfg, store); stats.Misses != 1 || stats.Hits != 1 {
		t.Fatalf("stats = %+v, want only the edited package re-analyzed", stats)
	}
}

func TestDisabledCacheIsNotUsed(t *testing.T) {
	dir := writeModule(t, map[string]string{"model/model.go": modelSrc})
	store := openCache(t)
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	if _, stats := scan(t, dir, cfg, store); stats != (cache.Stats{}) {
		t.Fatalf("stats = %+v, want no cache use", stats)
	}
}
