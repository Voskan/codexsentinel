// Package version provides build-time version information for CodexSentinel CLI.
package version

import (
	"fmt"
	"runtime/debug"
	"time"
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

// GetBuildInfo returns detailed build information including module info.
func GetBuildInfo() map[string]interface{} {
	info := map[string]interface{}{
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
		"go_version": "unknown",
		"module":     "unknown",
	}

	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		info["go_version"] = buildInfo.GoVersion
		if buildInfo.Main.Path != "" {
			info["module"] = buildInfo.Main.Path
		}
	}

	return info
}

// IsDevelopment returns true if this is a development build.
func IsDevelopment() bool {
	return Version == "dev" || Commit == "unknown"
}

// GetBuildTime returns the build time as a time.Time if available.
func GetBuildTime() (time.Time, error) {
	if BuildDate == "unknown" {
		return time.Time{}, fmt.Errorf("build date not available")
	}
	return time.Parse(time.RFC3339, BuildDate)
}

// GetShortCommit returns the short version of the commit hash.
func GetShortCommit() string {
	if len(Commit) > 8 {
		return Commit[:8]
	}
	return Commit
}
