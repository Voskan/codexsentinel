// Package fixer applies the suggested fixes of findings to source files.
package fixer

import (
	"errors"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// ApplyFixes writes the suggested fixes of issues to disk. Relative edit paths
// are resolved against rootDir, the directory the findings are relative to;
// an empty rootDir leaves them relative to the working directory.
//
// A fix whose edits overlap an already accepted fix is skipped, so the first
// fix for a span wins. Every rewritten file is formatted with go/format; a
// file that no longer parses is left untouched and reported as an error. It
// returns the files that were changed, as resolved paths, in sorted order.
func ApplyFixes(rootDir string, issues []result.Issue) ([]string, error) {
	byFile := map[string][]result.TextEdit{}
	for _, issue := range issues {
		if issue.Fix == nil || len(issue.Fix.Edits) == 0 {
			continue
		}
		edits := make([]result.TextEdit, 0, len(issue.Fix.Edits))
		ok := true
		for _, e := range issue.Fix.Edits {
			if e.File == "" || e.StartOffset < 0 || e.EndOffset < e.StartOffset {
				ok = false
				break
			}
			e.File = resolve(rootDir, e.File)
			if overlaps(byFile[e.File], e) || overlaps(edits, e) {
				ok = false
				break
			}
			edits = append(edits, e)
		}
		if !ok {
			continue
		}
		for _, e := range edits {
			byFile[e.File] = append(byFile[e.File], e)
		}
	}
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	var changed []string
	var errs []error
	for _, file := range files {
		if err := applyFileEdits(file, byFile[file]); err != nil {
			errs = append(errs, err)
			continue
		}
		changed = append(changed, file)
	}
	return changed, errors.Join(errs...)
}

func resolve(rootDir, file string) string {
	if rootDir == "" || filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(rootDir, filepath.FromSlash(file))
}

// overlaps reports whether e touches a span already edited in list. Two
// insertions at the same offset also conflict, since their order is undefined.
func overlaps(list []result.TextEdit, e result.TextEdit) bool {
	for _, o := range list {
		if e.File != o.File {
			continue
		}
		if e.StartOffset < o.EndOffset && o.StartOffset < e.EndOffset || e.StartOffset == o.StartOffset {
			return true
		}
	}
	return false
}

func applyFileEdits(file string, edits []result.TextEdit) error {
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].StartOffset > edits[j].StartOffset })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		if e.EndOffset > len(out) {
			return fmt.Errorf("%s: fix is out of range; the file changed since the scan", file)
		}
		out = append(out[:e.StartOffset:e.StartOffset], append([]byte(e.NewText), out[e.EndOffset:]...)...)
	}
	formatted, err := format.Source(out)
	if err != nil {
		return fmt.Errorf("%s: fixed source does not parse: %w", file, err)
	}
	return os.WriteFile(file, formatted, info.Mode().Perm())
}
