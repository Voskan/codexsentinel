package git

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LineRange is an inclusive range of line numbers in the new version of a file.
type LineRange struct {
	Start int
	End   int
}

// ChangedLines maps slash-separated file paths to the line ranges that were
// added or modified.
type ChangedLines map[string][]LineRange

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ParseUnifiedDiff extracts the changed line ranges of the new files from a
// unified diff. Pure deletions contribute no ranges; deleted files are skipped.
func ParseUnifiedDiff(r io.Reader) (ChangedLines, error) {
	changed := ChangedLines{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			current = diffPath(strings.TrimPrefix(line, "+++ "))
			if current != "" {
				if _, ok := changed[current]; !ok {
					changed[current] = nil
				}
			}
		case strings.HasPrefix(line, "@@ ") && current != "":
			m := hunkHeader.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("malformed hunk header %q", line)
			}
			start, _ := strconv.Atoi(m[1])
			count := 1
			if m[2] != "" {
				count, _ = strconv.Atoi(m[2])
			}
			if count > 0 {
				changed[current] = append(changed[current], LineRange{Start: start, End: start + count - 1})
			}
		}
	}
	return changed, scanner.Err()
}

// diffPath returns the path of a "+++" header without its "b/" prefix, or ""
// for /dev/null.
func diffPath(p string) string {
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	if strings.HasPrefix(p, `"`) {
		if unquoted, err := strconv.Unquote(p); err == nil {
			p = unquoted
		}
	}
	if p == "/dev/null" {
		return ""
	}
	return strings.TrimPrefix(p, "b/")
}

// Contains reports whether line of file was added or modified.
func (c ChangedLines) Contains(file string, line int) bool {
	for _, r := range c[filepath.ToSlash(file)] {
		if line >= r.Start && line <= r.End {
			return true
		}
	}
	return false
}

// Touched reports whether file appears in the diff.
func (c ChangedLines) Touched(file string) bool {
	_, ok := c[filepath.ToSlash(file)]
	return ok
}

// Diff returns the lines changed between ref and the working tree of the
// repository containing dir, including untracked files (which count as
// entirely changed). Paths are relative to dir; changes outside dir are dropped.
func Diff(ctx context.Context, dir, ref string) (ChangedLines, error) {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("invalid git reference %q", ref)
	}
	dir, err := filepath.Abs(dir)
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
	repoChanges, err := ParseUnifiedDiff(strings.NewReader(out))
	if err != nil {
		return nil, err
	}
	untracked, err := runGit(ctx, top, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	for _, file := range strings.Split(untracked, "\x00") {
		if file != "" {
			repoChanges[file] = []LineRange{{Start: 1, End: math.MaxInt}}
		}
	}
	changed := ChangedLines{}
	for file, ranges := range repoChanges {
		rel, err := filepath.Rel(dir, filepath.Join(top, filepath.FromSlash(file)))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		changed[filepath.ToSlash(rel)] = ranges
	}
	return changed, nil
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
