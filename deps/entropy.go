// Package deps provides analysis of dependencies and potential secrets.
package deps

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// EntropyFinding represents a high-entropy string found in code.
type EntropyFinding struct {
	Value     string  // The actual string value
	Entropy   float64 // Shannon entropy score
	File      string  // Source file path
	Line      int     // Line number
	IsComment bool    // Whether it was found in a comment
}

// AnalyzeHighEntropyStrings scans files for suspiciously random strings.
func AnalyzeHighEntropyStrings(files []string, minLength int, threshold float64) ([]EntropyFinding, error) {
	var findings []EntropyFinding
	fset := token.NewFileSet()

	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Parse for string literals
		node, err := parser.ParseFile(fset, path, content, parser.ParseComments)
		if err != nil {
			continue
		}

		// Extract string literals
		ast.Inspect(node, func(n ast.Node) bool {
			basic, ok := n.(*ast.BasicLit)
			if !ok || basic.Kind != token.STRING {
				return true
			}

			val := strings.Trim(basic.Value, "`\"'")
			val = sanitize(val)

			if len(val) < minLength {
				return true
			}

			ent := shannonEntropy(val)
			if ent >= threshold {
				pos := fset.Position(basic.Pos())
				findings = append(findings, EntropyFinding{
					Value:     val,
					Entropy:   ent,
					File:      filepath.ToSlash(pos.Filename),
					Line:      pos.Line,
					IsComment: false,
				})
			}
			return true
		})

		// Also scan comments
		for _, comment := range node.Comments {
			for _, c := range comment.List {
				words := strings.Fields(c.Text)
				for _, word := range words {
					word = strings.Trim(word, `"'`)
					word = sanitize(word)

					if len(word) < minLength {
						continue
					}
					ent := shannonEntropy(word)
					if ent >= threshold {
						pos := fset.Position(comment.Pos())
						findings = append(findings, EntropyFinding{
							Value:     word,
							Entropy:   ent,
							File:      filepath.ToSlash(pos.Filename),
							Line:      pos.Line,
							IsComment: true,
						})
					}
				}
			}
		}
	}

	return findings, nil
}

// sanitize removes whitespace and non-printable characters from string.
func sanitize(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy += -p * math.Log2(p)
	}
	return entropy
}
