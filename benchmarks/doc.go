// Package benchmarks measures detection quality and speed of the analysis
// engine on two corpora in corpus/: vulnerable-app, a multi-package service
// with known defects listed in its manifest.json, and safe-app, the same
// service written safely, on which no finding is expected. Each corpus is a
// separate module, so neither is part of this module's packages.
package benchmarks
