// Package git provides utilities to extract Git metadata for files and lines.
package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CommitMeta represents metadata about a Git commit.
type CommitMeta struct {
	Hash      string    // Commit SHA
	Author    string    // Author name
	Email     string    // Author email
	Timestamp time.Time // Commit date
	Message   string    // Commit message
}

// BlameInfo holds blame metadata for a specific line in a file.
type BlameInfo struct {
	CommitHash string // Commit SHA
	Author     string // Author name
	Email      string // Author email
	Timestamp  time.Time
	Summary    string // Commit message summary
	Line       int    // Line number (1-based)
}

// GitMetadata represents complete Git repository information.
type GitMetadata struct {
	RepoRoot    string    // Repository root path
	Branch      string    // Current branch name
	CommitHash  string    // Full commit hash
	CommitShort string    // Short commit hash (first 8 chars)
	Author      string    // Author name
	Email       string    // Author email
	Message     string    // Commit message
	Timestamp   time.Time // Commit timestamp
	IsDirty     bool      // Whether working directory has uncommitted changes
}

// gitOutput runs git in dir and returns its standard output.
func gitOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	return cmd.Output()
}

// GetGitMetadata returns the metadata of the Git repository containing dir.
func GetGitMetadata(dir string) (*GitMetadata, error) {
	repoRoot, err := RepoRoot(dir)
	if err != nil {
		return nil, err
	}

	metadata := &GitMetadata{
		RepoRoot: repoRoot,
	}

	// Get current branch
	if branch, err := getCurrentBranch(dir); err == nil {
		metadata.Branch = branch
	}

	// Get latest commit info
	if commit, err := LatestCommit(dir); err == nil && commit != nil {
		metadata.CommitHash = commit.Hash
		if len(commit.Hash) >= 8 {
			metadata.CommitShort = commit.Hash[:8]
		}
		metadata.Author = commit.Author
		metadata.Email = commit.Email
		metadata.Message = commit.Message
		metadata.Timestamp = commit.Timestamp
	}

	// Check if working directory is dirty
	if isDirty, err := checkIfDirty(dir); err == nil {
		metadata.IsDirty = isDirty
	}

	return metadata, nil
}

// getCurrentBranch returns the current branch name.
func getCurrentBranch(dir string) (string, error) {
	out, err := gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// checkIfDirty checks if the working directory has uncommitted changes.
func checkIfDirty(dir string) (bool, error) {
	out, err := gitOutput(dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return len(strings.TrimSpace(string(out))) > 0, nil
}

// RepoRoot returns the root directory of the Git repository containing dir.
func RepoRoot(dir string) (string, error) {
	out, err := gitOutput(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// LatestCommit returns metadata for the latest commit of the repository
// containing dir.
func LatestCommit(dir string) (*CommitMeta, error) {
	out, err := gitOutput(dir, "log", "-1", "--pretty=format:%H%n%an%n%ae%n%at%n%s")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 5 {
		return nil, nil
	}

	timestamp, err := parseUnixTimestamp(lines[3])
	if err != nil {
		return nil, err
	}

	return &CommitMeta{
		Hash:      lines[0],
		Author:    lines[1],
		Email:     lines[2],
		Timestamp: timestamp,
		Message:   lines[4],
	}, nil
}

// BlameLine returns blame metadata for a line of file, relative to dir.
func BlameLine(dir, file string, line int) (*BlameInfo, error) {
	file = filepath.ToSlash(file)
	cmd := exec.Command("git", "blame", "--porcelain", "-L", formatLineRange(line), "--", file)
	cmd.Dir = dir
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return parseBlameOutput(stdout.String(), line)
}

// parseBlameOutput parses the output of `git blame --porcelain`.
func parseBlameOutput(out string, line int) (*BlameInfo, error) {
	var (
		hash    string
		author  string
		email   string
		tstamp  time.Time
		summary string
	)

	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return nil, nil
	}

	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "author "):
			author = strings.TrimPrefix(l, "author ")
		case strings.HasPrefix(l, "author-mail "):
			email = strings.Trim(strings.TrimPrefix(l, "author-mail "), "<>")
		case strings.HasPrefix(l, "author-time "):
			t, err := parseUnixTimestamp(strings.TrimPrefix(l, "author-time "))
			if err == nil {
				tstamp = t
			}
		case strings.HasPrefix(l, "summary "):
			summary = strings.TrimPrefix(l, "summary ")
		case len(l) > 40 && hash == "":
			parts := strings.Fields(l)
			if len(parts) >= 1 {
				hash = parts[0]
			}
		}
	}

	if hash == "" {
		return nil, nil
	}

	return &BlameInfo{
		CommitHash: hash,
		Author:     author,
		Email:      email,
		Timestamp:  tstamp,
		Summary:    summary,
		Line:       line,
	}, nil
}

// formatLineRange formats the line range for git blame: "N,N"
func formatLineRange(line int) string {
	return fmt.Sprintf("%d,%d", line, line)
}

// parseUnixTimestamp parses a Unix timestamp string into time.Time.
func parseUnixTimestamp(s string) (time.Time, error) {
	sec, err := parseInt(s)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

// parseInt parses a string into int64.
func parseInt(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
