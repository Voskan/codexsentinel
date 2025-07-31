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

// AnalyzeHighEntropyStrings scans files for suspiciously random strings with improved accuracy
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

		// Extract string literals with context analysis
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

			// Check if this is a safe pattern before calculating entropy
			if isSafeEntropyPattern(val, n) {
				return true
			}

			ent := shannonEntropy(val)
			if ent >= threshold {
				// Additional context check
				if !isLikelySecret(val, n) {
					return true
				}
				
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

		// Also scan comments with improved filtering
		for _, comment := range node.Comments {
			for _, c := range comment.List {
				words := strings.Fields(c.Text)
				for _, word := range words {
					word = strings.Trim(word, `"'`)
					word = sanitize(word)

					if len(word) < minLength {
						continue
					}
					
					// Skip safe patterns in comments
					if isSafeEntropyPattern(word, nil) {
						continue
					}
					
					ent := shannonEntropy(word)
					if ent >= threshold {
						// Additional context check for comments
						if !isLikelySecret(word, nil) {
							continue
						}
						
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

// isSafeEntropyPattern checks if a string is a safe pattern that shouldn't trigger entropy warnings
func isSafeEntropyPattern(val string, node ast.Node) bool {
	valLower := strings.ToLower(val)
	
	// Common safe patterns
	safePatterns := []string{
		// UUID patterns
		"00000000-0000-0000-0000-000000000000",
		"12345678-1234-1234-1234-123456789abc",
		
		// Test data patterns
		"test", "example", "sample", "demo", "mock", "fake",
		"dummy", "placeholder", "template", "default",
		
		// Hash patterns (common in tests)
		"sha256", "md5", "sha1", "bcrypt",
		
		// Common configuration patterns
		"localhost", "127.0.0.1", "0.0.0.0",
		"admin", "user", "password", "secret",
		
		// File paths and URLs
		"http://", "https://", "file://", "ftp://",
		"/tmp/", "/var/", "/usr/", "/home/",
		
		// Common strings in Go
		"golang", "go.mod", "go.sum", "main.go",
		"package", "import", "func", "var", "const",
	}
	
	for _, pattern := range safePatterns {
		if strings.Contains(valLower, pattern) {
			return true
		}
	}
	
	// Check for variable assignments that suggest it's not a secret
	if node != nil {
		if isVariableAssignment(node) {
			return true
		}
	}
	
	return false
}

// isLikelySecret checks if a high-entropy string is likely to be a secret
func isLikelySecret(val string, node ast.Node) bool {
	valLower := strings.ToLower(val)
	
	// Patterns that suggest secrets
	secretPatterns := []string{
		"key", "token", "secret", "password", "auth",
		"private", "credential", "api", "access",
		"jwt", "bearer", "oauth", "session",
	}
	
	for _, pattern := range secretPatterns {
		if strings.Contains(valLower, pattern) {
			return true
		}
	}
	
	// Check for variable names that suggest secrets
	if node != nil {
		if isSecretVariable(node) {
			return true
		}
	}
	
	// If it's a very long string with high entropy, it might be a secret
	if len(val) > 32 {
		return true
	}
	
	return false
}

// isVariableAssignment checks if the node is part of a variable assignment
func isVariableAssignment(node ast.Node) bool {
	// This is a simplified check - in a real implementation you'd need more context
	// For now, we'll assume that if it's in a test file or has certain patterns, it's safe
	return false
}

// isSecretVariable checks if the variable name suggests it's a secret
func isSecretVariable(node ast.Node) bool {
	// This would need to check the variable name in the assignment
	// For now, we'll use a simplified approach
	return false
}
