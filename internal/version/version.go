// Package version provides build-time version information for CodexSentinel CLI.
package version

import (
	"fmt"
	"runtime/debug"
)

// These variables are intended to be set via -ldflags at build time.
var (
	Version   = "dev"     // CLI version tag, e.g., v1.0.0
	Commit    = "unknown" // Git commit SHA
	BuildDate = "unknown" // Build timestamp (e.g., 2025-07-09T12:34:56Z)
)

// FullVersion returns a human-readable version string.
func FullVersion() string {
	return fmt.Sprintf("CodexSentinel %s (commit: %s, built: %s)", Version, Commit, BuildDate)
}

// Info returns version info as a structured map for JSON/CLI use.
func Info() map[string]string {
	info := map[string]string{
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
	}

	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		info["go_version"] = buildInfo.GoVersion
	}

	return info
}
