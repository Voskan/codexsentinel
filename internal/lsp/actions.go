package lsp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/catalog"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/internal/jsonrpc"
	"github.com/Voskan/codexsentinel/report"
)

// fileLines reads a file split into lines; a missing file yields none.
func fileLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

// issueRange converts a finding's 1-based byte location to a 0-based UTF-16
// range. A finding without a column covers its whole line, one without an
// end runs to the end of its line, and one without a line marks the start of
// the file.
func issueRange(lines []string, loc result.Location) lspRange {
	if loc.Line <= 0 {
		return lspRange{}
	}
	text := lineText(lines, loc.Line)
	start := position{Line: loc.Line - 1, Character: utf16Column(text, loc.Column)}
	end := position{Line: loc.Line - 1, Character: utf16Len(text)}
	if loc.EndLine >= loc.Line && loc.EndColumn > 0 {
		end = position{Line: loc.EndLine - 1, Character: utf16Column(lineText(lines, loc.EndLine), loc.EndColumn)}
	}
	if end.Line == start.Line && end.Character < start.Character {
		end.Character = start.Character
	}
	return lspRange{Start: start, End: end}
}

func severityOf(s result.Severity) int {
	switch s {
	case result.SeverityCritical, result.SeverityHigh:
		return severityError
	case result.SeverityMedium:
		return severityWarning
	case result.SeverityLow:
		return severityInformation
	}
	return severityHint
}

// diagnosticsFor converts the findings of one file.
func diagnosticsFor(path string, issues []result.Issue) []diagnostic {
	lines := fileLines(path)
	diags := make([]diagnostic, 0, len(issues))
	for _, is := range issues {
		d := diagnostic{
			Range:    issueRange(lines, is.Location),
			Severity: severityOf(is.Severity),
			Code:     is.ID,
			Source:   "codexsentinel",
			Message:  diagnosticMessage(is),
		}
		if doc, ok := catalog.Lookup(is.ID); ok && doc.ID == is.ID {
			d.CodeDescription = &codeDescription{Href: catalog.DocURL(doc.ID)}
		} else if len(is.References) > 0 && is.References[0] != "" {
			d.CodeDescription = &codeDescription{Href: is.References[0]}
		}
		for _, step := range is.Trace {
			stepPath := step.Location.File
			if stepPath == "" {
				continue
			}
			d.RelatedInformation = append(d.RelatedInformation, diagnosticRelatedInformation{
				Location: location{URI: pathToURI(stepPath), Range: issueRange(fileLines(stepPath), step.Location)},
				Message:  strings.TrimSpace(step.Kind + ": " + step.Message),
			})
		}
		diags = append(diags, d)
	}
	return diags
}

// diagnosticMessage is the hover text: the description, the CWE and OWASP
// classification, the fix and the data flow.
func diagnosticMessage(is result.Issue) string {
	var b strings.Builder
	b.WriteString(is.Title)
	if is.Description != "" && is.Description != is.Title {
		b.WriteString(": " + is.Description)
	}
	var tags []string
	for _, t := range []string{is.CWE, is.OWASP} {
		if t != "" {
			tags = append(tags, t)
		}
	}
	if len(tags) > 0 {
		b.WriteString("\n[" + strings.Join(tags, ", ") + "]")
	}
	if is.Suggestion != "" {
		b.WriteString("\nFix: " + is.Suggestion)
	}
	if lines := report.TraceLines(is.Trace); len(lines) > 0 {
		b.WriteString("\nFlow:\n" + strings.Join(lines, "\n"))
	}
	return b.String()
}

// codeActions offers, for each finding overlapping the requested range, its
// fix and a suppression comment.
func (s *Server) codeActions(params json.RawMessage) (any, *jsonrpc.Error) {
	var p codeActionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, jsonrpc.Errorf(jsonrpc.CodeInvalidParams, "codeAction: %v", err)
	}
	path, ok := uriToPath(p.TextDocument.URI)
	if !ok {
		return []codeAction{}, nil
	}
	s.mu.Lock()
	issues := append([]result.Issue(nil), s.issues[path]...)
	s.mu.Unlock()
	lines := fileLines(path)
	actions := []codeAction{}
	for _, is := range issues {
		r := issueRange(lines, is.Location)
		if !overlaps(r, p.Range) {
			continue
		}
		diag := diagnosticsFor(path, []result.Issue{is})
		if is.Fix != nil && len(is.Fix.Edits) > 0 {
			title := is.Fix.Message
			if title == "" {
				title = "Fix " + is.ID
			}
			actions = append(actions, codeAction{
				Title: title, Kind: "quickfix", IsPreferred: true, Diagnostics: diag,
				Edit: &workspaceEdit{Changes: fixEdits(path, is.Fix.Edits)},
			})
		}
		if !s.ForbidSuppressions && is.Location.Line > 0 {
			end := position{Line: is.Location.Line - 1, Character: utf16Len(lineText(lines, is.Location.Line))}
			actions = append(actions, codeAction{
				Title: fmt.Sprintf("Suppress %s on this line", is.ID), Kind: "quickfix", Diagnostics: diag,
				Edit: &workspaceEdit{Changes: map[string][]textEdit{p.TextDocument.URI: {{
					Range:   lspRange{Start: end, End: end},
					NewText: fmt.Sprintf(" //codex:ignore %s -- TODO: document reason", is.ID),
				}}}},
			})
		}
	}
	return actions, nil
}

// fixEdits converts a fix's edits, grouped by document URI. Edit paths are
// absolute.
func fixEdits(issuePath string, edits []result.TextEdit) map[string][]textEdit {
	changes := map[string][]textEdit{}
	for _, e := range edits {
		path := issuePath
		if e.File != "" {
			path = e.File
		}
		lines := fileLines(path)
		r := lspRange{
			Start: position{Line: e.StartLine - 1, Character: utf16Column(lineText(lines, e.StartLine), e.StartColumn)},
			End:   position{Line: e.EndLine - 1, Character: utf16Column(lineText(lines, e.EndLine), e.EndColumn)},
		}
		uri := pathToURI(path)
		changes[uri] = append(changes[uri], textEdit{Range: r, NewText: e.NewText})
	}
	return changes
}

func overlaps(a, b lspRange) bool {
	return !before(a.End, b.Start) && !before(b.End, a.Start)
}

func before(a, b position) bool {
	return a.Line < b.Line || (a.Line == b.Line && a.Character < b.Character)
}
