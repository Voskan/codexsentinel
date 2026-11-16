package deps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// LicenseFinding represents a dependency and its detected license.
type LicenseFinding struct {
	Module      string // Module path (e.g. github.com/foo/bar)
	Version     string // Version (e.g. v1.2.3)
	License     string // SPDX identifier (e.g. MIT, GPL-3.0) or UNKNOWN
	Allowed     bool   // Whether it is in the allow list
	Denied      bool   // Whether it is in the deny list
	LicenseFile string // Path to the license file, if found
}

// listedModule is one object of `go list -m -json all`.
type listedModule struct {
	Path     string
	Version  string
	Dir      string
	Main     bool
	Indirect bool
	Replace  *listedModule
}

// AnalyzeLicenses detects the license of every module required by goModPath.
// Module directories come from `go list -m -json all`, which covers the module
// cache, vendoring and local replacements; when that is unavailable the vendor
// directory and $GOMODCACHE are searched directly.
func AnalyzeLicenses(goModPath string, allowList, denyList []string) ([]LicenseFinding, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}
	mod, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}
	rootDir := filepath.Dir(goModPath)
	dirs, _ := listModuleDirs(rootDir)

	var findings []LicenseFinding
	for _, req := range mod.Require {
		modPath, modVersion := req.Mod.Path, req.Mod.Version
		dir := dirs[modPath]
		if dir == "" {
			dir = fallbackModuleDir(rootDir, modPath, modVersion)
		}
		license, licensePath := "UNKNOWN", ""
		if dir != "" {
			license, licensePath = detectLicense(dir)
		}
		findings = append(findings, LicenseFinding{
			Module:      modPath,
			Version:     modVersion,
			License:     license,
			Allowed:     contains(allowList, license),
			Denied:      contains(denyList, license),
			LicenseFile: licensePath,
		})
	}
	return findings, nil
}

// listModuleDirs maps module paths to their source directories using the go command.
func listModuleDirs(dir string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-e", "-json", "all")
	cmd.Dir = dir
	// Never download or rewrite go.mod/go.sum: only modules already on disk matter.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	dirs := map[string]string{}
	dec := json.NewDecoder(out)
	for {
		var m listedModule
		if err := dec.Decode(&m); err != nil {
			if !errors.Is(err, io.EOF) {
				_ = cmd.Process.Kill()
			}
			break
		}
		d := m.Dir
		if m.Replace != nil && m.Replace.Dir != "" {
			d = m.Replace.Dir
		}
		if !m.Main && d != "" {
			dirs[m.Path] = d
		}
	}
	return dirs, cmd.Wait()
}

// fallbackModuleDir looks for a module in vendor/ and in the module cache.
func fallbackModuleDir(rootDir, modPath, version string) string {
	if dir := filepath.Join(rootDir, "vendor", filepath.FromSlash(modPath)); isDir(dir) {
		return dir
	}
	cache := moduleCacheDir()
	if cache == "" {
		return ""
	}
	escaped, err := module.EscapePath(modPath)
	if err != nil {
		return ""
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return ""
	}
	if dir := filepath.Join(cache, filepath.FromSlash(escaped)+"@"+escapedVersion); isDir(dir) {
		return dir
	}
	return ""
}

// moduleCacheDir returns $GOMODCACHE, defaulting to $GOPATH/pkg/mod.
func moduleCacheDir() string {
	if dir := os.Getenv("GOMODCACHE"); dir != "" {
		return dir
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gopath = filepath.Join(home, "go")
	}
	return filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
}

var licenseFileNames = []string{
	"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE-MIT", "LICENSE-APACHE", "LICENCE", "LICENCE.md", "LICENCE.txt",
	"COPYING", "COPYING.md", "COPYING.txt", "COPYING.LESSER", "UNLICENSE", "NOTICE",
}

// detectLicense finds and classifies the license file of a module directory.
func detectLicense(dir string) (string, string) {
	firstFound := ""
	for _, name := range licenseFileNames {
		p := filepath.Join(dir, name)
		if !exists(p) {
			continue
		}
		if firstFound == "" {
			firstFound = p
		}
		if kind := classifyLicense(p); kind != "UNKNOWN" {
			return kind, p
		}
	}
	return "UNKNOWN", firstFound
}

const licenseReadLimit = 16 << 10

// classifyLicense reads the start of a license file and returns its SPDX identifier.
func classifyLicense(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "UNKNOWN"
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, licenseReadLimit))
	if err != nil {
		return "UNKNOWN"
	}
	return ClassifyLicenseText(string(data))
}

var spdxMarker = regexp.MustCompile(`(?i)spdx-license-identifier:\s*([A-Za-z0-9.+-]+)`)

// ClassifyLicenseText identifies a license from its text and returns an SPDX
// identifier, or UNKNOWN.
func ClassifyLicenseText(text string) string {
	if m := spdxMarker.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	t := strings.ToLower(strings.Join(strings.Fields(text), " "))
	has := func(parts ...string) bool {
		for _, p := range parts {
			if !strings.Contains(t, p) {
				return false
			}
		}
		return true
	}
	version := func(v ...string) bool {
		for _, s := range v {
			if strings.Contains(t, "version "+s) || strings.Contains(t, "v"+s) || strings.Contains(t, "-"+s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("gnu affero general public license"):
		return "AGPL-3.0"
	case has("gnu lesser general public license"), has("gnu library general public license"):
		if version("3") {
			return "LGPL-3.0"
		}
		return "LGPL-2.1"
	case has("gnu general public license"):
		if version("3") {
			return "GPL-3.0"
		}
		return "GPL-2.0"
	case has("server side public license"):
		return "SSPL-1.0"
	case has("business source license"):
		return "BSL-1.1"
	case has("mozilla public license") && version("2.0"):
		return "MPL-2.0"
	case has("apache license") && version("2.0"), has("licensed under the apache license, version 2.0"):
		return "Apache-2.0"
	case has("this is free and unencumbered software released into the public domain"):
		return "Unlicense"
	case has("cc0 1.0"), has("cc0-1.0"), has("creative commons") && has("cc0"):
		return "CC0-1.0"
	case has("isc license"), has("permission to use, copy, modify, and/or distribute this software for any purpose"):
		return "ISC"
	case has("mit license"), has("permission is hereby granted, free of charge"):
		return "MIT"
	case has("redistribution and use in source and binary forms"):
		if has("neither the name") || has("to endorse or promote products") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	}
	return "UNKNOWN"
}

// exists checks whether a regular file exists.
func exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// contains reports whether list contains item, ignoring case.
func contains(list []string, item string) bool {
	for _, v := range list {
		if strings.EqualFold(v, item) {
			return true
		}
	}
	return false
}
