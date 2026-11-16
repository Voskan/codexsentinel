package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/result"
)

// DefaultFile is the conventional baseline file name.
const DefaultFile = ".codexsentinel.baseline.json"

// Version is the current baseline file format version.
const Version = 1

// Entry records one known finding.
type Entry struct {
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"rule_id"`
	File        string    `json:"file"`
	Function    string    `json:"function,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Baseline is the set of findings accepted as existing technical debt.
type Baseline struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
	index   map[string]bool
}

// New records the fingerprinted issues as a baseline.
func New(issues []result.Issue, now time.Time) *Baseline {
	b := &Baseline{Version: Version}
	seen := map[string]bool{}
	for _, issue := range issues {
		if issue.Fingerprint == "" || seen[issue.Fingerprint] {
			continue
		}
		seen[issue.Fingerprint] = true
		b.Entries = append(b.Entries, Entry{
			Fingerprint: issue.Fingerprint, RuleID: issue.ID, File: issue.Location.File,
			Function: issue.Location.Function, CreatedAt: now.UTC().Truncate(time.Second),
		})
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		a, c := b.Entries[i], b.Entries[j]
		if a.File != c.File {
			return a.File < c.File
		}
		if a.RuleID != c.RuleID {
			return a.RuleID < c.RuleID
		}
		return a.Fingerprint < c.Fingerprint
	})
	return b
}

// Load reads a baseline file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Version != Version {
		return nil, fmt.Errorf("unsupported baseline version %d in %s", b.Version, path)
	}
	return &b, nil
}

// Write stores the baseline as indented JSON.
func (b *Baseline) Write(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Contains reports whether the fingerprint is part of the baseline.
func (b *Baseline) Contains(fingerprint string) bool {
	if b.index == nil {
		b.index = make(map[string]bool, len(b.Entries))
		for _, e := range b.Entries {
			b.index[e.Fingerprint] = true
		}
	}
	return b.index[fingerprint]
}

// Filter returns the issues that are not part of the baseline and the number
// of issues it removed.
func (b *Baseline) Filter(issues []result.Issue) ([]result.Issue, int) {
	out := make([]result.Issue, 0, len(issues))
	for _, issue := range issues {
		if issue.Fingerprint != "" && b.Contains(issue.Fingerprint) {
			continue
		}
		out = append(out, issue)
	}
	return out, len(issues) - len(out)
}
