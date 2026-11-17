// Package ignore provides functionality for parsing and applying ignore rules
// defined in .codexsentinel.ignore file.
package ignore

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/Voskan/codexsentinel/v2/internal/matcher"
)

// IgnoreRule represents a single parsed ignore rule.
type IgnoreRule struct {
	File    string   // optional path glob relative to the project root; "" = any file
	Line    int      // optional line number, 0 = any line
	RuleIDs []string // rules to ignore; "*" ignores every rule
	Comment string   // optional comment after #
	raw     string   // original line (for debugging)
	files   *matcher.Matcher
	ids     *matcher.Matcher
}

// Manager holds and evaluates parsed ignore rules.
type Manager struct {
	rules []IgnoreRule
	root  string
	mu    sync.RWMutex
}

// NewManager creates a new empty ignore manager.
func NewManager() *Manager {
	return &Manager{}
}

// SetRoot sets the project root that file patterns are relative to. Absolute
// paths passed to IsIgnored are made relative to it.
func (m *Manager) SetRoot(root string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.root = root
}

// LoadFile parses the ignore rules from the given file path.
func (m *Manager) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return m.Load(f)
}

// Load parses ignore rules from r, one per line.
func (m *Manager) Load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	m.mu.Lock()
	defer m.mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rule := parseLine(line); rule != nil {
			rule.raw = line
			m.rules = append(m.rules, *rule)
		}
	}
	return scanner.Err()
}

// Rules returns the parsed rules.
func (m *Manager) Rules() []IgnoreRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]IgnoreRule(nil), m.rules...)
}

// IsIgnored checks if a given rule ID at file:line should be ignored.
func (m *Manager) IsIgnored(file string, line int, ruleID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	file = m.relative(file)
	for _, r := range m.rules {
		if !r.ids.Match(ruleID) {
			continue
		}
		if r.files != nil && !r.files.Match(file) {
			continue
		}
		if r.Line != 0 && r.Line != line {
			continue
		}
		return true
	}
	return false
}

func (m *Manager) relative(file string) string {
	if m.root != "" && filepath.IsAbs(file) {
		if rel, err := filepath.Rel(m.root, file); err == nil {
			file = rel
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(file), "./")
}

// parseLine parses a single ignore rule line.
// Syntax: [path[:line]] rule-id[,rule-id...] [# comment]
//
// A single token is a path pattern ignoring every rule when it looks like a
// path (contains "/", "*" or ".go", or starts with "."), and a rule ID
// ignored in every file otherwise.
//
// Examples:
//
//	handlers/user.go:42 sql-injection # this is fine
//	pkg/legacy/*.go sql-injection,xss # legacy admin
//	**/*.pb.go
//	global-variable
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
	rule := &IgnoreRule{Comment: comment}
	if len(parts) == 1 {
		if looksLikePath(parts[0]) {
			rule.File = parts[0]
			rule.RuleIDs = []string{"*"}
		} else {
			rule.RuleIDs = []string{parts[0]}
		}
	} else {
		loc := parts[0]
		if i := strings.LastIndex(loc, ":"); i > 0 {
			if n, err := strconv.Atoi(loc[i+1:]); err == nil {
				rule.Line = n
				loc = loc[:i]
			}
		}
		rule.File = loc
		for _, id := range strings.Split(strings.Join(parts[1:], ""), ",") {
			if id = strings.TrimSpace(id); id != "" {
				rule.RuleIDs = append(rule.RuleIDs, id)
			}
		}
		if len(rule.RuleIDs) == 0 {
			return nil
		}
	}
	rule.ids = matcher.New(rule.RuleIDs)
	if rule.File != "" {
		rule.files = matcher.New([]string{rule.File})
	}
	return rule
}

func looksLikePath(token string) bool {
	return strings.ContainsAny(token, "/*") || strings.Contains(token, ".go") || strings.HasPrefix(token, ".")
}
