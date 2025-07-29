package builtin

import (
	"go/ast"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"golang.org/x/tools/go/analysis"
)

// RegisterCryptoWeakRule registers the weak cryptographic algorithms detection rule.
func RegisterCryptoWeakRule(ctx *analyzer.AnalyzerContext) {
	ctx.RegisterRule(&analyzer.Rule{
		ID:       "crypto-weak-algorithm",
		Title:    "Cryptographic Failures (A02:2025)",
		Category: "security",
		Severity: result.SeverityHigh,
		Summary:  "Use of weak cryptographic algorithms (MD5, SHA1, DES, etc.) may lead to security vulnerabilities.",
		Matcher:  matchCryptoWeakAlgorithms,
	})
}

// matchCryptoWeakAlgorithms detects weak cryptographic algorithms
func matchCryptoWeakAlgorithms(ctx *analyzer.AnalyzerContext, pass *analysis.Pass) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				// Check for weak hash functions
				if isWeakHashFunction(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Hash Function Usage",
						Description: "Use of weak hash function (MD5, SHA1) may lead to security vulnerabilities",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use SHA-256, SHA-512, or bcrypt for password hashing",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html"},
					})
				}

				// Check for weak encryption algorithms
				if isWeakEncryptionAlgorithm(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Encryption Algorithm Usage",
						Description: "Use of weak encryption algorithm (DES, 3DES, RC4) may lead to security vulnerabilities",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use AES-256, ChaCha20-Poly1305, or other modern encryption algorithms",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
					})
				}

				// Check for weak random number generation
				if isWeakRandomGeneration(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Random Number Generation",
						Description: "Use of weak random number generation (math/rand) for cryptographic purposes",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use crypto/rand for cryptographic random number generation",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"},
					})
				}

				// Check for weak key derivation functions
				if isWeakKeyDerivation(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Key Derivation Function",
						Description: "Use of weak key derivation function may lead to security vulnerabilities",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use PBKDF2, Argon2, or bcrypt with appropriate parameters",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html"},
					})
				}

				// Check for weak signature algorithms
				if isWeakSignatureAlgorithm(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Signature Algorithm",
						Description: "Use of weak signature algorithm may lead to security vulnerabilities",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use RSA with 2048+ bits, ECDSA with P-256+, or Ed25519",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
					})
				}

				// Check for weak cipher modes
				if isWeakCipherMode(x) {
					pos := ctx.GetFset().Position(x.Pos())
					ctx.Report(result.Issue{
						ID:          "crypto-weak-algorithm",
						Title:       "Weak Cipher Mode",
						Description: "Use of weak cipher mode (ECB, CBC without proper padding) may lead to security vulnerabilities",
						Severity:    result.SeverityHigh,
						Location:    result.NewLocationFromPos(pos, "", ""),
						Category:    "security",
						Suggestion:  "Use GCM, ChaCha20-Poly1305, or CBC with proper padding and IV",
						References:  []string{"https://owasp.org/www-project-cheat-sheets/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"},
					})
				}
			}
			return true
		})
	}
}

// isWeakHashFunction checks if call is a weak hash function
func isWeakHashFunction(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak hash functions
		weakHashPatterns := []string{
			"md5", "sha1", "sha128", "md4", "md2",
			"sum", "new", "write", "hash",
		}

		for _, pattern := range weakHashPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from crypto/md5 or crypto/sha1
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "md5" || ident.Name == "sha1" {
							return true
						}
					}
				}
				
				// Check for direct package usage
				if ident, ok := fun.X.(*ast.Ident); ok {
					if ident.Name == "md5" || ident.Name == "sha1" {
						return true
					}
				}
			}
		}

		// Check for specific weak hash function calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "crypto" {
					weakHashFuncs := []string{"MD5", "SHA1", "MD4", "MD2"}
					for _, funcName := range weakHashFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isWeakEncryptionAlgorithm checks if call is a weak encryption algorithm
func isWeakEncryptionAlgorithm(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak encryption algorithms
		weakEncryptionPatterns := []string{
			"des", "3des", "rc4", "blowfish", "cast5", "cast128",
			"newcipher", "newblockcipher", "encrypt", "decrypt",
		}

		for _, pattern := range weakEncryptionPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from crypto/des or other weak crypto packages
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "des" || ident.Name == "rc4" {
							return true
						}
					}
				}
				
				// Check for direct package usage
				if ident, ok := fun.X.(*ast.Ident); ok {
					if ident.Name == "des" || ident.Name == "rc4" {
						return true
					}
				}
			}
		}

		// Check for specific weak encryption function calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "crypto" {
					weakEncryptionFuncs := []string{"DES", "TripleDES", "RC4"}
					for _, funcName := range weakEncryptionFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isWeakRandomGeneration checks if call is weak random number generation
func isWeakRandomGeneration(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak random generation
		weakRandomPatterns := []string{
			"rand", "random", "intn", "float64", "int31", "int63",
		}

		for _, pattern := range weakRandomPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from math/rand (weak) instead of crypto/rand (strong)
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "rand" {
							// Check if it's from math/rand
							if sel.Sel.Name == "Intn" || sel.Sel.Name == "Float64" || 
							   sel.Sel.Name == "Int31" || sel.Sel.Name == "Int63" {
								return true
							}
						}
					}
				}
				
				// Check for direct math/rand usage
				if ident, ok := fun.X.(*ast.Ident); ok {
					if ident.Name == "rand" {
						weakRandFuncs := []string{"Intn", "Float64", "Int31", "Int63", "Int", "Float32"}
						for _, funcName := range weakRandFuncs {
							if fun.Sel.Name == funcName {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// isWeakKeyDerivation checks if call is a weak key derivation function
func isWeakKeyDerivation(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak key derivation functions
		weakKDFPatterns := []string{
			"pbkdf1", "md5", "sha1", "weak", "simple",
		}

		for _, pattern := range weakKDFPatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from weak crypto packages
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "crypto" || ident.Name == "hash" {
							return true
						}
					}
				}
			}
		}

		// Check for specific weak KDF function calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "crypto" {
					weakKDFFuncs := []string{"PBKDF1", "MD5", "SHA1"}
					for _, funcName := range weakKDFFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isWeakSignatureAlgorithm checks if call is a weak signature algorithm
func isWeakSignatureAlgorithm(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak signature algorithms
		weakSignaturePatterns := []string{
			"md5", "sha1", "rsa1024", "dsa1024", "weak", "small",
		}

		for _, pattern := range weakSignaturePatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from weak crypto packages
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "crypto" || ident.Name == "rsa" {
							return true
						}
					}
				}
			}
		}

		// Check for specific weak signature function calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "crypto" {
					weakSignatureFuncs := []string{"MD5", "SHA1", "RSA1024", "DSA1024"}
					for _, funcName := range weakSignatureFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// isWeakCipherMode checks if call is a weak cipher mode
func isWeakCipherMode(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := strings.ToLower(fun.Sel.Name)
		
		// Check for weak cipher modes
		weakCipherModePatterns := []string{
			"ecb", "cbc", "weak", "mode", "block",
		}

		for _, pattern := range weakCipherModePatterns {
			if strings.Contains(funcName, pattern) {
				// Check if it's from crypto/cipher with weak modes
				if sel, ok := fun.X.(*ast.SelectorExpr); ok {
					if ident, ok := sel.X.(*ast.Ident); ok {
						if ident.Name == "cipher" {
							weakModes := []string{"ECB", "CBC"}
							for _, mode := range weakModes {
								if fun.Sel.Name == mode {
									return true
								}
							}
						}
					}
				}
			}
		}

		// Check for specific weak cipher mode calls
		if sel, ok := fun.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "crypto" {
					weakCipherModeFuncs := []string{"ECB", "CBC", "WeakMode"}
					for _, funcName := range weakCipherModeFuncs {
						if fun.Sel.Name == funcName {
							return true
						}
					}
				}
			}
		}
	}
	return false
} 