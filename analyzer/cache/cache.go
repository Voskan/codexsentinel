// Package cache stores per-package analysis results on disk, addressed by a
// hash of everything the results depend on. A changed input produces a new
// key, so entries never need to be invalidated explicitly.
package cache

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// EnvDir overrides the default cache directory when set.
const EnvDir = "CODEXSENTINEL_CACHE_DIR"

const entrySuffix = ".json.gz"

// Stats counts cache lookups of one Cache value.
type Stats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Writes int64 `json:"writes"`
}

// Cache is a directory of entries stored as <dir>/<ab>/<key>.json.gz, where ab
// are the first two characters of the key. It is safe for concurrent use by
// several goroutines and processes: entries are written to a temporary file
// and renamed into place, so readers never see a partial entry.
type Cache struct {
	dir                  string
	hits, misses, writes atomic.Int64
}

// ResolveDir returns the cache directory to use: configured when it is set,
// otherwise $CODEXSENTINEL_CACHE_DIR, otherwise codexsentinel/cache-v1 in the
// user cache directory.
func ResolveDir(configured string) (string, error) {
	if configured != "" {
		return filepath.Abs(configured)
	}
	if env := os.Getenv(EnvDir); env != "" {
		return filepath.Abs(env)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache directory: %w", err)
	}
	return filepath.Join(base, "codexsentinel", "cache-v1"), nil
}

// Open returns a cache in dir, creating the directory when needed.
func Open(dir string) (*Cache, error) {
	if dir == "" {
		return nil, errors.New("cache directory is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	return &Cache{dir: dir}, nil
}

// Dir returns the cache directory.
func (c *Cache) Dir() string { return c.dir }

// Stats returns the lookups counted so far.
func (c *Cache) Stats() Stats {
	return Stats{Hits: c.hits.Load(), Misses: c.misses.Load(), Writes: c.writes.Load()}
}

func (c *Cache) path(key string) (string, error) {
	if len(key) < 3 || strings.ContainsAny(key, `/\.`) {
		return "", fmt.Errorf("invalid cache key %q", key)
	}
	return filepath.Join(c.dir, key[:2], key+entrySuffix), nil
}

// Get decodes the entry for key into v and reports whether it was found. An
// unreadable or corrupt entry counts as a miss.
func (c *Cache) Get(key string, v any) bool {
	if c.get(key, v) {
		c.hits.Add(1)
		return true
	}
	c.misses.Add(1)
	return false
}

func (c *Cache) get(key string, v any) bool {
	path, err := c.path(key)
	if err != nil {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return false
	}
	defer zr.Close()
	return json.NewDecoder(zr).Decode(v) == nil
}

// Put stores v under key. The entry becomes visible atomically.
func (c *Cache) Put(key string, v any) (err error) {
	path, err := c.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	zw := gzip.NewWriter(tmp)
	if err = json.NewEncoder(zw).Encode(v); err != nil {
		return err
	}
	if err = zw.Close(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	c.writes.Add(1)
	return nil
}

// Usage reports the number of entries in dir and their total size in bytes.
// A missing directory is empty.
func Usage(dir string) (entries int, size int64, err error) {
	err = walkEntries(dir, func(path string, info fs.FileInfo) error {
		entries++
		size += info.Size()
		return nil
	})
	return entries, size, err
}

// Clean removes every cache entry from dir and the shard directories that
// become empty. Files that are not cache entries are left alone.
func Clean(dir string) (removed int, err error) {
	err = walkEntries(dir, func(path string, info fs.FileInfo) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		removed++
		return nil
	})
	if err != nil {
		return removed, err
	}
	shards, _ := os.ReadDir(dir)
	for _, shard := range shards {
		if shard.IsDir() && isShard(shard.Name()) {
			_ = os.Remove(filepath.Join(dir, shard.Name())) // fails while not empty
		}
	}
	return removed, nil
}

// walkEntries calls fn for every entry and stale temporary file in the shard
// directories of dir.
func walkEntries(dir string, fn func(string, fs.FileInfo) error) error {
	shards, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, shard := range shards {
		if !shard.IsDir() || !isShard(shard.Name()) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, shard.Name()))
		if err != nil {
			return err
		}
		for _, file := range files {
			name := file.Name()
			if file.IsDir() || !(strings.HasSuffix(name, entrySuffix) || strings.HasPrefix(name, ".tmp-")) {
				continue
			}
			info, err := file.Info()
			if err != nil {
				continue
			}
			if err := fn(filepath.Join(dir, shard.Name(), name), info); err != nil {
				return err
			}
		}
	}
	return nil
}

func isShard(name string) bool {
	if len(name) != 2 {
		return false
	}
	for _, r := range name {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
