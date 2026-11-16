package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var (
	zipSlipMeta = ruleMeta{ID: "archive-zip-slip", Title: "Archive Path Traversal (Zip Slip)", Severity: result.SeverityCritical, CWE: "CWE-22", OWASP: "A01:2025", Confidence: 0.9,
		Suggestion: "Extract through an *os.Root (os.OpenRoot(dest)) or reject entries that are not filepath.IsLocal before joining them with the destination.",
		References: []string{"https://security.snyk.io/research/zip-slip-vulnerability", "https://go.dev/blog/osroot"}}
	decompressionBombMeta = ruleMeta{ID: "archive-decompression-bomb", Title: "Unbounded Decompression", Severity: result.SeverityMedium, CWE: "CWE-409", OWASP: "A06:2025", Confidence: 0.8,
		Suggestion: "Copy decompressed data through io.LimitReader(rc, maxBytes) or io.CopyN and fail when the limit is reached.",
		References: []string{"https://cwe.mitre.org/data/definitions/409.html"}}
	gobDecodeMeta = ruleMeta{ID: "unsafe-gob-decode", Title: "Gob Decoding of Untrusted Input", Severity: result.SeverityHigh, CWE: "CWE-502", OWASP: "A08:2025",
		Suggestion: "Do not decode gob from untrusted clients; use a schema-validated format such as JSON with http.MaxBytesReader.",
		References: []string{"https://pkg.go.dev/encoding/gob#hdr-Security"}}
)

// RegisterDataIntegrityRule reports unsafe archive extraction and gob
// decoding of request bodies.
func RegisterDataIntegrityRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{zipSlipMeta, decompressionBombMeta, gobDecodeMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				checkArchives(r, info, unit)
			}
		}
	})
}

// archiveEntryName reports whether e reads the name of a zip or tar entry.
func archiveEntryName(info *types.Info, e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	s, ok := info.Selections[sel]
	if !ok || s.Kind() != types.FieldVal {
		return false
	}
	field := s.Obj()
	if field.Pkg() == nil {
		return false
	}
	switch field.Pkg().Path() {
	case "archive/zip":
		return field.Name() == "Name"
	case "archive/tar":
		return field.Name() == "Name" || field.Name() == "Linkname"
	}
	return false
}

// decompressedStream reports whether e opens a decompressing reader.
func decompressedStream(info *types.Info, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := calleeFunc(info, call)
	return isMethod(fn, "archive/zip", "File", "Open") ||
		isFunc(fn, "compress/gzip", "NewReader") || isFunc(fn, "compress/zlib", "NewReader", "NewReaderDict") ||
		isFunc(fn, "compress/flate", "NewReader", "NewReaderDict") || isFunc(fn, "compress/bzip2", "NewReader") ||
		isFunc(fn, "compress/lzw", "NewReader") || isFunc(fn, "github.com/klauspost/compress/zstd", "NewReader")
}

func checkArchives(r *reporter, info *types.Info, unit funcUnit) {
	assigns := assignments(info, unit.Body)
	validated := false
	inspectShallow(unit.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			fn := calleeFunc(info, call)
			if isFunc(fn, "strings", "HasPrefix") || isFunc(fn, "path/filepath", "IsLocal", "Rel", "Localize") {
				validated = true
			}
		}
		return true
	})
	nameBarrier := func(call *ast.CallExpr) bool {
		return isFunc(calleeFunc(info, call), "path/filepath", "Base")
	}
	limitBarrier := func(call *ast.CallExpr) bool {
		fn := calleeFunc(info, call)
		return isFunc(fn, "io", "LimitReader") || isFunc(fn, "net/http", "MaxBytesReader")
	}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		switch {
		case isFunc(fn, "os", "Create", "OpenFile", "Mkdir", "MkdirAll", "WriteFile", "Symlink", "Link"):
			if validated {
				return true
			}
			for _, arg := range call.Args {
				if derivesFrom(info, assigns, arg, func(e ast.Expr) bool { return archiveEntryName(info, e) }, nameBarrier) {
					r.report(zipSlipMeta, call, "Archive entry name reaches "+callName(call)+" without being confined to the destination; entries like ../../etc/cron.d/x escape it.")
					break
				}
			}
		case isFunc(fn, "io", "Copy", "CopyBuffer") && len(call.Args) >= 2, isFunc(fn, "io", "ReadAll") && len(call.Args) == 1:
			src := call.Args[len(call.Args)-1]
			if fn.Name() != "ReadAll" {
				src = call.Args[1]
			}
			if derivesFrom(info, assigns, src, func(e ast.Expr) bool { return decompressedStream(info, e) }, limitBarrier) {
				r.report(decompressionBombMeta, call, "Decompressed data is copied without a size limit; a small archive can expand to gigabytes.")
			}
		case isFunc(fn, "encoding/gob", "NewDecoder") && len(call.Args) == 1:
			if derivesFrom(info, assigns, call.Args[0], func(e ast.Expr) bool { return requestBody(info, e) }, nil) {
				r.report(gobDecodeMeta, call, "gob decodes data from the HTTP request body; crafted input can trigger huge allocations or panics.")
			}
		}
		return true
	})
}
