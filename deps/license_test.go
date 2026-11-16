package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLicenseClassifyText(t *testing.T) {
	cases := map[string]string{
		"spdx":       "// Copyright 2024 Example\n// SPDX-License-Identifier: MPL-2.0\n",
		"apache":     "                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n\n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
		"mit-header": "MIT License\n\nCopyright (c) 2020 Example",
		"mit-text":   "Copyright (c) 2016 Example\n\nPermission is hereby granted, free\nof charge, to any person obtaining a copy of this software",
		"bsd3":       "Copyright (c) 2009 The Go Authors.\n\nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n\n * Neither the name of Google LLC nor the names of its\ncontributors may be used to endorse or promote products derived from\nthis software without specific prior written permission.",
		"bsd2":       "Copyright (c) 2013 Example\n\nRedistribution and use in source and binary\nforms, with or without modification, are permitted provided that the\nfollowing conditions are met:\n\n1. Redistributions of source code must retain the above copyright notice.\n2. Redistributions in binary form must reproduce the above copyright notice.",
		"isc":        "ISC License\n\nCopyright (c) 2015 Example",
		"isc-text":   "Permission to use, copy, modify, and/or distribute this software for any\npurpose with or without fee is hereby granted",
		"mpl":        "Mozilla Public License Version 2.0\n==================================",
		"lgpl3":      "                   GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007",
		"lgpl21":     "                  GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 2.1, February 1999",
		"agpl":       "                    GNU AFFERO GENERAL PUBLIC LICENSE\n                       Version 3, 19 November 2007",
		"gpl3":       "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007",
		"gpl2":       "                    GNU GENERAL PUBLIC LICENSE\n                       Version 2, June 1991",
		"bsl":        "Business Source License 1.1\n\nParameters\n\nLicensor: Example",
		"sspl":       "                     Server Side Public License\n                     VERSION 1, OCTOBER 16, 2018",
		"unlicense":  "This is free and unencumbered software released into the public domain.",
		"cc0":        "Creative Commons Legal Code\n\nCC0 1.0 Universal",
		"unknown":    "All rights reserved.",
	}
	want := map[string]string{
		"spdx": "MPL-2.0", "apache": "Apache-2.0", "mit-header": "MIT", "mit-text": "MIT", "bsd3": "BSD-3-Clause", "bsd2": "BSD-2-Clause",
		"isc": "ISC", "isc-text": "ISC", "mpl": "MPL-2.0", "lgpl3": "LGPL-3.0", "lgpl21": "LGPL-2.1", "agpl": "AGPL-3.0", "gpl3": "GPL-3.0",
		"gpl2": "GPL-2.0", "bsl": "BSL-1.1", "sspl": "SSPL-1.0", "unlicense": "Unlicense", "cc0": "CC0-1.0", "unknown": "UNKNOWN",
	}
	for name, text := range cases {
		if got := ClassifyLicenseText(text); got != want[name] {
			t.Errorf("%s: got %s, want %s", name, got, want[name])
		}
	}
}

func TestLicenseModuleCacheFallback(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	dir := filepath.Join(cache, "github.com", "!user!name", "!mixed!case@v1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE.txt"), []byte("ISC License\n\nCopyright (c) 2024"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if got := fallbackModuleDir(root, "github.com/UserName/MixedCase", "v1.0.0"); got != dir {
		t.Fatalf("fallbackModuleDir = %q, want %q", got, dir)
	}
	goMod := filepath.Join(root, "go.mod")
	if err := os.WriteFile(goMod, []byte("module example.com/app\n\ngo 1.24\n\nrequire github.com/UserName/MixedCase v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeLicenses(goMod, []string{"isc"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].License != "ISC" || !findings[0].Allowed || findings[0].LicenseFile != filepath.Join(dir, "LICENSE.txt") {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestLicenseVendorFallback(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	root := t.TempDir()
	vendored := filepath.Join(root, "vendor", "example.org", "lib")
	if err := os.MkdirAll(vendored, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendored, "COPYING"), []byte("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := fallbackModuleDir(root, "example.org/lib", "v0.1.0"); got != vendored {
		t.Fatalf("vendor dir not found: %q", got)
	}
	if kind, _ := detectLicense(vendored); kind != "GPL-3.0" {
		t.Fatalf("detectLicense = %s", kind)
	}
}

func TestLicenseRepositoryModules(t *testing.T) {
	goMod, err := filepath.Abs(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeLicenses(goMod, []string{"MIT", "Apache-2.0", "BSD-3-Clause"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LicenseFinding{}
	for _, f := range findings {
		got[f.Module] = f
	}
	for module, license := range map[string]string{"github.com/spf13/cobra": "Apache-2.0", "github.com/spf13/pflag": "BSD-3-Clause", "go.uber.org/zap": "MIT"} {
		f, ok := got[module]
		if !ok {
			t.Fatalf("%s is not required by go.mod", module)
		}
		if f.LicenseFile == "" && f.License == "UNKNOWN" {
			t.Skipf("module sources for %s are not in the module cache; run go mod download", module)
		}
		if f.License != license || !f.Allowed {
			t.Errorf("%s: got %s (allowed=%v), want %s", module, f.License, f.Allowed, license)
		}
	}
}
