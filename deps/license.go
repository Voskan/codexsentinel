// Package deps provides analysis of dependency licenses in Go modules.
package deps

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// LicenseFinding represents a dependency and its associated license.
type LicenseFinding struct {
	Module      string // Module path (e.g. github.com/foo/bar)
	Version     string // Version (e.g. v1.2.3)
	License     string // Detected license (e.g. MIT, GPL-3.0)
	Allowed     bool   // Whether it's in allow-list
	Denied      bool   // Whether it's in deny-list
	LicenseFile string // Path to license file if found
}

// AnalyzeLicenses analyzes go.mod and go.sum for dependency licenses.
func AnalyzeLicenses(goModPath string, allowList, denyList []string) ([]LicenseFinding, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	mod, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	rootDir := filepath.Dir(goModPath)
	var findings []LicenseFinding

	for _, req := range mod.Require {
		modPath := req.Mod.Path
		modVersion := req.Mod.Version

		license, licensePath := detectLicense(modPath, modVersion, rootDir)

		f := LicenseFinding{
			Module:      modPath,
			Version:     modVersion,
			License:     license,
			Allowed:     contains(allowList, license),
			Denied:      contains(denyList, license),
			LicenseFile: licensePath,
		}
		findings = append(findings, f)
	}

	return findings, nil
}

// detectLicense attempts to read LICENSE file in module cache.
// Fallback: unknown license.
func detectLicense(modPath, modVersion, projectRoot string) (string, string) {
	_ = strings.ReplaceAll(modPath, "/", "_") + "@" + modVersion // moduleName not used
	modCache := filepath.Join(projectRoot, "vendor", modPath)    // for vendored projects

	licenseFiles := []string{
		"LICENSE", "LICENSE.md", "LICENSE.txt",
		"LICENSE-MIT", "COPYING", "COPYING.txt",
	}

	for _, name := range licenseFiles {
		p := filepath.Join(modCache, name)
		if exists(p) {
			kind := classifyLicense(p)
			return kind, p
		}
	}

	return "UNKNOWN", ""
}

// classifyLicense reads and classifies the license type from file content.
func classifyLicense(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "UNKNOWN"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		switch {
		case strings.Contains(line, "mit license"):
			return "MIT"
		case strings.Contains(line, "apache license"):
			return "Apache-2.0"
		case strings.Contains(line, "gnu general public license v3"):
			return "GPL-3.0"
		case strings.Contains(line, "gnu affero general public license"):
			return "AGPL-3.0"
		case strings.Contains(line, "mozilla public license"):
			return "MPL-2.0"
		case strings.Contains(line, "business source license"):
			return "BSL-1.1"
		}
	}

	return "UNKNOWN"
}

// exists checks whether a file exists.
func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// contains checks if a slice contains a string.
func contains(list []string, item string) bool {
	for _, v := range list {
		if strings.EqualFold(v, item) {
			return true
		}
	}
	return false
}
