package lsp

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// The subset of Language Server Protocol types the server uses.

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type lspRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type location struct {
	URI   string   `json:"uri"`
	Range lspRange `json:"range"`
}

type diagnosticRelatedInformation struct {
	Location location `json:"location"`
	Message  string   `json:"message"`
}

type codeDescription struct {
	Href string `json:"href"`
}

type diagnostic struct {
	Range              lspRange                       `json:"range"`
	Severity           int                            `json:"severity"`
	Code               string                         `json:"code"`
	CodeDescription    *codeDescription               `json:"codeDescription,omitempty"`
	Source             string                         `json:"source"`
	Message            string                         `json:"message"`
	RelatedInformation []diagnosticRelatedInformation `json:"relatedInformation,omitempty"`
}

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

type textEdit struct {
	Range   lspRange `json:"range"`
	NewText string   `json:"newText"`
}

type workspaceEdit struct {
	Changes map[string][]textEdit `json:"changes"`
}

type codeAction struct {
	Title       string         `json:"title"`
	Kind        string         `json:"kind"`
	Diagnostics []diagnostic   `json:"diagnostics,omitempty"`
	IsPreferred bool           `json:"isPreferred,omitempty"`
	Edit        *workspaceEdit `json:"edit,omitempty"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

type initializeParams struct {
	RootURI          string `json:"rootUri"`
	RootPath         string `json:"rootPath"`
	WorkspaceFolders []struct {
		URI string `json:"uri"`
	} `json:"workspaceFolders"`
}

type documentParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type codeActionParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Range        lspRange               `json:"range"`
}

// Diagnostic severities.
const (
	severityError       = 1
	severityWarning     = 2
	severityInformation = 3
	severityHint        = 4
)

// uriToPath converts a file URI to a local path. Windows drive paths such as
// file:///C:/src arrive with a leading slash that is removed.
func uriToPath(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" {
		return "", false
	}
	p := u.Path
	if runtime.GOOS == "windows" {
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		if u.Host != "" && u.Host != "localhost" {
			p = "//" + u.Host + p // UNC path
		}
	}
	return filepath.Clean(filepath.FromSlash(p)), true
}

// pathToURI converts an absolute local path to a file URI.
func pathToURI(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive letter
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// utf16Column converts a 1-based byte column of a line into the 0-based
// UTF-16 offset LSP expects. Columns past the end of the line are clamped.
func utf16Column(line string, byteCol int) int {
	if byteCol <= 1 {
		return 0
	}
	if byteCol-1 < len(line) {
		line = line[:byteCol-1]
	}
	n := 0
	for len(line) > 0 {
		r, size := utf8.DecodeRuneInString(line)
		line = line[size:]
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// utf16Len returns the length of s in UTF-16 code units.
func utf16Len(s string) int { return utf16Column(s, len(s)+1) }

// lineText returns line n (1-based) of the file, or "".
func lineText(lines []string, n int) string {
	if n < 1 || n > len(lines) {
		return ""
	}
	return strings.TrimSuffix(lines[n-1], "\r")
}
