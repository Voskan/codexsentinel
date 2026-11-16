package git

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/config"
)

// yamlLine is the shape of one line of a YAML file, enough to find the key a
// list item or nested value belongs to.
type yamlLine struct {
	indent int
	item   bool   // starts with "- "
	key    string // "" when the line has no key
	value  string // inline value after the key, or the item text
}

func parseYAMLLine(line string) (yamlLine, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return yamlLine{}, false
	}
	l := yamlLine{indent: len(line) - len(trimmed)}
	if trimmed == "-" || strings.HasPrefix(trimmed, "- ") {
		l.item = true
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
	}
	trimmed = stripYAMLComment(trimmed)
	if i := strings.Index(trimmed, ":"); i > 0 && (i == len(trimmed)-1 || trimmed[i+1] == ' ') && !strings.ContainsAny(trimmed[:i], `"'[{`) {
		l.key = strings.TrimSpace(trimmed[:i])
		l.value = strings.TrimSpace(trimmed[i+1:])
	} else {
		l.value = trimmed
	}
	return l, true
}

func stripYAMLComment(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// parentKeys returns the keys of the blocks that line i belongs to, from the
// innermost outwards. A list item may sit at its key's own indentation.
func parentKeys(lines []string, i int, l yamlLine) []string {
	var keys []string
	indent, item := l.indent, l.item
	for j := i - 1; j >= 0 && (indent > 0 || item); j-- {
		p, ok := parseYAMLLine(lines[j])
		if !ok {
			continue
		}
		if p.indent < indent || (item && p.indent == indent && !p.item && p.key != "" && p.value == "") {
			keys = append(keys, p.key)
			indent, item = p.indent, p.item
		}
	}
	return keys
}

// configSuppressions reports added configuration lines that disable rules,
// exclude paths or relax thresholds compared with the removed value of the
// same key, or with the default when the key is new.
func configSuppressions(lines []string, added func(int) bool, removedLines []string) []AddedSuppression {
	oldValues := map[string]string{}
	removedItems := map[string]int{}
	for _, r := range removedLines {
		if l, ok := parseYAMLLine(r); ok {
			if l.key != "" && l.value != "" {
				oldValues[l.key] = l.value
			}
			removedItems[strings.TrimSpace(stripYAMLComment(r))]++
		}
	}
	var out []AddedSuppression
	for i, raw := range lines {
		l, ok := parseYAMLLine(raw)
		if !ok || !added(i+1) {
			continue
		}
		text := strings.TrimSpace(stripYAMLComment(raw))
		if removedItems[text] > 0 {
			removedItems[text]--
			continue
		}
		if weakeningLine(lines, i, l, oldValues) {
			out = append(out, AddedSuppression{Line: i + 1, Kind: "configuration", Text: text})
		}
	}
	return out
}

func weakeningLine(lines []string, i int, l yamlLine, oldValues map[string]string) bool {
	if weakeningKeys[l.key] && l.value != "" {
		old, hadOld := oldValues[l.key]
		return weakerValue(l.key, l.value, old, hadOld)
	}
	for _, k := range parentKeys(lines, i, l) {
		if !weakeningKeys[k] {
			continue
		}
		if k == "excluded_paths" && l.item && isDefaultExclusion(l.value) {
			return false
		}
		return true
	}
	return false
}

// weakerValue reports whether setting key to value hides more findings than
// the old value, or than the default when there was none.
func weakerValue(key, value, old string, hadOld bool) bool {
	value, old = unquote(value), unquote(old)
	switch key {
	case "enable_inline_ignore":
		return value == "true" && hadOld && old == "false"
	case "forbid_new_suppressions":
		return value == "false" && hadOld && old == "true"
	case "disable-all":
		return value == "true"
	case "min_confidence":
		base := config.DefaultConfig.Suppression.MinConfidence
		if hadOld {
			base, _ = strconv.ParseFloat(old, 64)
		}
		v, err := strconv.ParseFloat(value, 64)
		return err != nil || v > base
	case "fail_on_severity":
		return hadOld && severityRank(value) > severityRank(old)
	}
	items := listItems(value)
	if items == nil {
		return true // a scalar or a mapping: treat as one new entry
	}
	oldItems := listItems(old)
	for _, item := range items {
		if slices.Contains(oldItems, item) || (key == "excluded_paths" && isDefaultExclusion(item)) {
			continue
		}
		return true
	}
	return false
}

// listItems splits an inline YAML list; it returns nil for other values.
func listItems(v string) []string {
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil
	}
	items := []string{}
	for _, part := range strings.Split(v[1:len(v)-1], ",") {
		if part = unquote(strings.TrimSpace(part)); part != "" {
			items = append(items, part)
		}
	}
	return items
}

func unquote(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return strings.Trim(s, `'`)
}

func isDefaultExclusion(item string) bool {
	item = strings.Trim(unquote(item), "/")
	item = strings.TrimSuffix(strings.TrimPrefix(item, "**/"), "/**")
	return slices.Contains(config.DefaultConfig.Scan.ExcludedPaths, item)
}

// severityRank orders fail_on_severity values; an empty or unknown value
// fails on nothing and ranks highest.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 5
}
