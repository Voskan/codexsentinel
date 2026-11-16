package git

import (
	"bufio"
	"context"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// SuppressionRuleID identifies findings for suppressions added in a diff.
const SuppressionRuleID = "unauthorized-suppression-added"

// AllowSuppressionsEnv is the environment variable that approves new
// suppressions, typically set by CI when a security reviewer has labeled the
// change.
const AllowSuppressionsEnv = "CODEX_ALLOW_SUPPRESSIONS"

// AddedSuppression is a suppression introduced by a change: an inline
// directive, an ignore-file entry or a configuration setting that weakens the
// analysis.
type AddedSuppression struct {
	File string // slash-separated, relative to the scanned directory
	Line int
	Kind string // "inline directive", "ignore file entry" or "configuration"
	Text string
}

// Issue converts the suppression into a finding. It is produced after inline
// and file-based suppressions are applied, so it cannot suppress itself.
func (s AddedSuppression) Issue() result.Issue {
	return result.Issue{
		ID:          SuppressionRuleID,
		Title:       "Unauthorized Security Suppression Added in Diff",
		Severity:    result.SeverityCritical,
		Category:    "security",
		CWE:         "CWE-693",
		Confidence:  1,
		Location:    result.Location{File: s.File, Line: s.Line},
		Description: fmt.Sprintf("The change adds a %s that hides findings: %s", s.Kind, s.Text),
		Suggestion:  "Fix the finding instead, or have the change approved by a security reviewer so CI sets " + AllowSuppressionsEnv + "=1.",
	}
}

// configFiles are the files whose settings can weaken the analysis.
var configFiles = map[string]bool{
	".codexsentinel.yaml": true, ".codexsentinel.yml": true, "codex.yaml": true, ".codex.yml": true,
	".golangci.yml": true, ".golangci.yaml": true,
}

// weakeningKeys are configuration keys whose added values can hide findings.
var weakeningKeys = map[string]bool{
	"disabled": true, "excluded_paths": true, "enable_inline_ignore": true, "min_confidence": true,
	"fail_on_severity": true, "forbid_new_suppressions": true,
	// golangci-lint
	"disable": true, "disable-all": true, "exclude": true, "exclude-rules": true, "exclude-dirs": true,
	"exclude-files": true, "exclusions": true,
}

// fileChange holds the added lines of one file and the removed lines that
// they may merely restate.
type fileChange struct {
	added   []int
	removed []string
}

// ScanAddedSuppressions reports suppressions added between ref and the
// working tree of the repository containing rootDir, including untracked
// files. Go directives (//codex:ignore, //nolint, #nosec) count only inside
// comments; entries of .codexsentinel.ignore and of extraIgnoreFiles count
// unless they are comments; configuration lines count when they disable
// rules, exclude paths or relax thresholds. A suppression that a removed line
// of the same file already contained (a moved or reformatted line) is not new.
func ScanAddedSuppressions(ctx context.Context, rootDir, ref string, extraIgnoreFiles ...string) ([]AddedSuppression, error) {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("invalid git reference %q", ref)
	}
	dir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	top, err := runGit(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	top = strings.TrimSpace(top)
	out, err := runGit(ctx, top, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", ref, "--")
	if err != nil {
		return nil, err
	}
	changes, err := parseAddedLines(strings.NewReader(out))
	if err != nil {
		return nil, err
	}
	untracked, err := runGit(ctx, top, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	for _, file := range strings.Split(untracked, "\x00") {
		if file != "" {
			changes[file] = &fileChange{added: []int{math.MaxInt}}
		}
	}
	ignoreFiles := map[string]bool{".codexsentinel.ignore": true}
	for _, f := range extraIgnoreFiles {
		ignoreFiles[filepath.Base(f)] = true
	}
	var found []AddedSuppression
	for file, change := range changes {
		rel, err := filepath.Rel(dir, filepath.Join(top, filepath.FromSlash(file)))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		hits, err := inspectFile(filepath.Join(top, filepath.FromSlash(file)), change, ignoreFiles)
		if err != nil {
			return nil, err
		}
		for _, h := range hits {
			h.File = filepath.ToSlash(rel)
			found = append(found, h)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	return found, nil
}

// parseAddedLines returns, per file, the new line numbers of added lines and
// the text of removed lines. Header lines are recognized only before a
// file's first hunk, so added content that starts with "++" is not mistaken
// for a header.
func parseAddedLines(r io.Reader) (map[string]*fileChange, error) {
	changes := map[string]*fileChange{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var current *fileChange
	inHeader, next := false, 0
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			inHeader, current = true, nil
		case inHeader && strings.HasPrefix(line, "+++ "):
			if p := diffPath(strings.TrimPrefix(line, "+++ ")); p != "" {
				current = &fileChange{}
				changes[p] = current
			}
		case strings.HasPrefix(line, "@@ "):
			inHeader = false
			m := hunkHeader.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("malformed hunk header %q", line)
			}
			next, _ = strconv.Atoi(m[1])
		case inHeader || current == nil:
		case strings.HasPrefix(line, "+"):
			current.added = append(current.added, next)
			next++
		case strings.HasPrefix(line, "-"):
			current.removed = append(current.removed, line[1:])
		case strings.HasPrefix(line, " "):
			next++
		}
	}
	return changes, sc.Err()
}

// inspectFile finds suppressions on the added lines of a file in the working
// tree. An added line of math.MaxInt stands for a wholly new file.
func inspectFile(path string, change *fileChange, ignoreFiles map[string]bool) ([]AddedSuppression, error) {
	base := filepath.Base(path)
	isGo := strings.HasSuffix(base, ".go")
	if !isGo && !ignoreFiles[base] && !configFiles[base] {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	added := func(line int) bool { return isAdded(change.added, line) }
	switch {
	case isGo:
		return goSuppressions(data, added, removedGoDirectives(change.removed)), nil
	case ignoreFiles[base]:
		return ignoreEntries(lines, added, change.removed), nil
	default:
		return configSuppressions(lines, added, change.removed), nil
	}
}

func isAdded(added []int, line int) bool {
	for _, a := range added {
		if a == line || a == math.MaxInt {
			return true
		}
	}
	return false
}

// goSuppressions lexes the whole file so that directive-like text inside
// string literals is ignored, then reports directives in comments that start
// on added lines.
func goSuppressions(src []byte, added func(int) bool, removed map[string]int) []AddedSuppression {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)
	var out []AddedSuppression
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		if tok != token.COMMENT {
			continue
		}
		line := fset.Position(pos).Line
		if !added(line) {
			continue
		}
		if d := directiveOf(lit); d != "" {
			if removed[d] > 0 {
				removed[d]--
				continue
			}
			out = append(out, AddedSuppression{Line: line, Kind: "inline directive", Text: strings.TrimSpace(lit)})
		}
	}
}

// directiveOf returns the normalized suppression directive in a comment, or
// "" if the comment is not one. The reason is dropped so that rewording it
// does not count as a new suppression.
func directiveOf(comment string) string {
	text := comment
	switch {
	case strings.HasPrefix(text, "//"):
		text = text[2:]
	case strings.HasPrefix(text, "/*"):
		text = strings.TrimSuffix(text[2:], "*/")
	default:
		return ""
	}
	text = strings.TrimSpace(text)
	var d string
	switch {
	case strings.HasPrefix(text, "codex:ignore"):
		d = text
	case strings.HasPrefix(text, "nolint") && (len(text) == 6 || text[6] == ':' || text[6] == ' '):
		d = text
	case strings.HasPrefix(text, "#nosec"):
		d = text
	default:
		return ""
	}
	for _, sep := range []string{" -- ", " //"} {
		if i := strings.Index(d, sep); i >= 0 {
			d = d[:i]
		}
	}
	return strings.Join(strings.Fields(d), " ")
}

// removedGoDirectives counts the directives on removed lines, lexing each
// line on its own.
func removedGoDirectives(lines []string) map[string]int {
	out := map[string]int{}
	for _, line := range lines {
		src := []byte(line)
		fset := token.NewFileSet()
		var s scanner.Scanner
		s.Init(fset.AddFile("", fset.Base(), len(src)), src, func(token.Position, string) {}, scanner.ScanComments)
		for {
			_, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok == token.COMMENT {
				if d := directiveOf(lit); d != "" {
					out[d]++
				}
			}
		}
	}
	return out
}

// ignoreEntries reports added entries of an ignore file that were not
// present among its removed lines.
func ignoreEntries(lines []string, added func(int) bool, removedLines []string) []AddedSuppression {
	removed := map[string]int{}
	for _, l := range removedLines {
		if e := ignoreEntry(l); e != "" {
			removed[e]++
		}
	}
	var out []AddedSuppression
	for i, l := range lines {
		e := ignoreEntry(l)
		if e == "" || !added(i+1) {
			continue
		}
		if removed[e] > 0 {
			removed[e]--
			continue
		}
		out = append(out, AddedSuppression{Line: i + 1, Kind: "ignore file entry", Text: e})
	}
	return out
}

func ignoreEntry(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	return strings.Join(strings.Fields(line), " ")
}
