// Package ignore provides functionality for parsing and applying ignore rules
// defined in .codexsentinel.ignore file.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// IgnoreRule represents a single parsed ignore rule.
type IgnoreRule struct {
	File     string // optional file path, may contain wildcards
	Line     int    // optional line number, 0 = any line
	RuleID   string // rule to ignore, required
	Comment  string // optional comment after #
	raw      string // original line (for debugging)
}

// Manager holds and evaluates parsed ignore rules.
type Manager struct {
	rules []IgnoreRule
	mu    sync.RWMutex
}

// NewManager creates a new empty ignore manager.
func NewManager() *Manager {
	return &Manager{}
}

// LoadFile parses the ignore rules from the given file path.
func (m *Manager) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0

	m.mu.Lock()
	defer m.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNo++

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule := parseLine(line)
		if rule != nil {
			rule.raw = line
			m.rules = append(m.rules, *rule)
		}
	}

	return scanner.Err()
}

// IsIgnored checks if a given rule ID at file:line should be ignored.
func (m *Manager) IsIgnored(file string, line int, ruleID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file = filepath.ToSlash(file)

	for _, r := range m.rules {
		if r.RuleID != ruleID {
			continue
		}
		if r.File != "" {
			match, err := filepath.Match(r.File, file)
			if err != nil || !match {
				continue
			}
		}
		if r.Line != 0 && r.Line != line {
			continue
		}
		return true
	}

	return false
}

// parseLine parses a single ignore rule line.
// Syntax: [path[:line]] rule-id [# comment]
//
// Examples:
//   handlers/user.go:42 sql-injection # this is fine
//   handlers/* xss-template
//   xss-template
func parseLine(line string) *IgnoreRule {
	comment := ""
	if idx := strings.Index(line, "#"); idx >= 0 {
		comment = strings.TrimSpace(line[idx+1:])
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	var file string
	var lineNum int
	var rule string

	if len(parts) == 1 {
		rule = parts[0]
	} else {
		loc := parts[0]
		rule = parts[1]

		if strings.Contains(loc, ":") {
			split := strings.SplitN(loc, ":", 2)
			file = strings.TrimSpace(split[0])
			if n, err := parseLineNumber(split[1]); err == nil {
				lineNum = n
			}
		} else {
			file = loc
		}
	}

	return &IgnoreRule{
		File:    file,
		Line:    lineNum,
		RuleID:  rule,
		Comment: comment,
	}
}

// parseLineNumber parses an integer line number.
func parseLineNumber(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}
