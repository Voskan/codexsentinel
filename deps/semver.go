package deps

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

// canonicalVersion returns v in the "vX.Y.Z" form used by golang.org/x/mod/semver.
func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "go")
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if c := semver.Canonical(v); c != "" {
		if build := semver.Build(v); build != "" {
			return c + build
		}
		return c
	}
	return ""
}

// compareVersions compares two versions with or without the "v" prefix.
func compareVersions(a, b string) int {
	return semver.Compare(canonicalVersion(a), canonicalVersion(b))
}

// MatchGHSARange reports whether version satisfies a GitHub advisory range
// such as "< 1.2.4", ">= 1.0.0, < 1.1.5" or "= 2.1.0".
func MatchGHSARange(rangeExpr, version string) (bool, error) {
	v := canonicalVersion(version)
	if v == "" {
		return false, fmt.Errorf("invalid version %q", version)
	}
	rangeExpr = strings.TrimSpace(rangeExpr)
	if rangeExpr == "" {
		return false, fmt.Errorf("empty version range")
	}
	for _, part := range strings.Split(rangeExpr, ",") {
		part = strings.TrimSpace(part)
		op := ""
		for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
			if strings.HasPrefix(part, candidate) {
				op = candidate
				break
			}
		}
		bound := canonicalVersion(strings.TrimSpace(strings.TrimPrefix(part, op)))
		if bound == "" {
			return false, fmt.Errorf("invalid constraint %q", part)
		}
		cmp := semver.Compare(v, bound)
		var ok bool
		switch op {
		case ">=":
			ok = cmp >= 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case "<":
			ok = cmp < 0
		case "=", "==", "":
			ok = cmp == 0
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// osvEvent is one boundary of an OSV SEMVER range.
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// inOSVRange reports whether version falls inside the events of an OSV
// SEMVER range, and returns the fixing version of the matching interval.
func inOSVRange(events []osvEvent, version string) (bool, string) {
	affected, fixed := false, ""
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || compareVersions(version, e.Introduced) >= 0 {
				affected, fixed = true, ""
			}
		case e.Fixed != "":
			if affected && compareVersions(version, e.Fixed) >= 0 {
				affected = false
			} else if affected && fixed == "" {
				fixed = e.Fixed
			}
		case e.LastAffected != "":
			if affected && compareVersions(version, e.LastAffected) > 0 {
				affected = false
			}
		}
	}
	return affected, fixed
}
