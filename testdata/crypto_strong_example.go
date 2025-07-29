package testdata

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// Strong hash function usage - SHA-256
func strongSHA256Hash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Strong hash function usage - SHA-512
func strongSHA512Hash(data []byte) string {
	h := sha512.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Strong hash function usage - SHA-256 with crypto/sha256
func strongSHA256HashCrypto(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Strong hash function usage - SHA-512 with crypto/sha512
func strongSHA512HashCrypto(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// Strong encryption algorithm - AES-256-GCM
func strongAES256GCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	
	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Encrypt and seal
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	
	// Combine nonce and ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}

// Strong encryption algorithm - ChaCha20-Poly1305
func strongChaCha20Poly1305Encrypt(key, plaintext []byte) ([]byte, error) {
	// Note: ChaCha20-Poly1305 is available in Go 1.20+
	// This is a placeholder for demonstration
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	
	// Create GCM mode (as alternative)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Encrypt and seal
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	
	// Combine nonce and ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}

// Strong random number generation - crypto/rand
func strongRandomNumber() (int, error) {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return 0, err
	}
	
	// Convert to int (simplified)
	result := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | 
	          int(randomBytes[2])<<8 | int(randomBytes[3])
	return result % 1000, nil
}

// Strong random number generation - crypto/rand for bytes
func strongRandomBytes(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// Strong key derivation - PBKDF2
func strongPBKDF2KeyDerivation(password []byte, salt []byte) []byte {
	// Use SHA-256 with 100,000 iterations
	derivedKey := pbkdf2.Key(password, salt, 32, 100000, sha256.New)
	return derivedKey
}

// Strong key derivation - Scrypt
func strongScryptKeyDerivation(password []byte, salt []byte) ([]byte, error) {
	// Use Scrypt with strong parameters
	derivedKey, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return derivedKey, nil
}

// Strong password hashing - bcrypt
func strongPasswordHash(password string) (string, error) {
	// Use bcrypt with cost factor 12
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Strong password verification - bcrypt
func strongPasswordVerify(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// Strong signature algorithm - RSA with SHA-256
func strongRSASignature(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Using SHA-256 for signature (strong)
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
}

// Strong signature algorithm - RSA with SHA-512
func strongRSASignatureSHA512(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Using SHA-512 for signature (strong)
	h := sha512.New()
	h.Write(data)
	hashed := h.Sum(nil)
	
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed)
}

// Strong cipher mode - AES-GCM
func strongAESGCMEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	
	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Encrypt and seal
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	
	// Combine nonce and ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}

// Strong cipher mode - AES-CBC with proper padding and IV
func strongAESCBCEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Generate random IV
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	
	// Pad plaintext to block size
	paddedPlaintext := padPKCS7(plaintext, block.BlockSize())
	
	// Create CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)
	
	// Combine IV and ciphertext
	result := append(iv, ciphertext...)
	return result, nil
}

// Strong HMAC - using SHA-256
func strongHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Strong HMAC - using SHA-512
func strongHMACSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Strong certificate - using SHA-256
func strongCertificateSHA256() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "strong-cert-sha256",
		},
		// Using SHA-256 for signature (strong)
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}

// Strong certificate - using SHA-512
func strongCertificateSHA512() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "strong-cert-sha512",
		},
		// Using SHA-512 for signature (strong)
		SignatureAlgorithm: x509.SHA512WithRSA,
	}
}

// Strong TLS configuration - using strong ciphers
func strongTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,     // Strong AES-GCM
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,      // Strong ChaCha20-Poly1305
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,   // Strong AES-GCM
		},
	}
}

// Helper function for PKCS7 padding
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// Example usage functions
func exampleStrongHashUsage() {
	data := []byte("sensitive data")
	
	// Strong hash usage
	sha256Hash := strongSHA256Hash(data)
	sha512Hash := strongSHA512Hash(data)
	
	fmt.Printf("SHA-256: %s\n", sha256Hash)
	fmt.Printf("SHA-512: %s\n", sha512Hash)
}

func exampleStrongEncryptionUsage() {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	
	plaintext := []byte("sensitive data")
	
	// Strong encryption usage
	aesGCMCipher, _ := strongAES256GCMEncrypt(key, plaintext)
	chachaCipher, _ := strongChaCha20Poly1305Encrypt(key, plaintext)
	
	fmt.Printf("AES-GCM: %x\n", aesGCMCipher)
	fmt.Printf("ChaCha20-Poly1305: %x\n", chachaCipher)
}

func exampleStrongRandomUsage() {
	// Strong random usage
	strongNum, _ := strongRandomNumber()
	strongBytes, _ := strongRandomBytes(16)
	
	fmt.Printf("Strong Random: %d\n", strongNum)
	fmt.Printf("Strong Bytes: %x\n", strongBytes)
}

func exampleStrongKeyDerivationUsage() {
	password := []byte("password123")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		fmt.Printf("Error generating salt: %v\n", err)
		return
	}
	
	// Strong key derivation usage
	pbkdf2Key := strongPBKDF2KeyDerivation(password, salt)
	scryptKey, _ := strongScryptKeyDerivation(password, salt)
	
	fmt.Printf("PBKDF2 Key: %x\n", pbkdf2Key)
	fmt.Printf("Scrypt Key: %x\n", scryptKey)
}

func exampleStrongPasswordHashUsage() {
	password := "password123"
	
	// Strong password hash usage
	strongHash, _ := strongPasswordHash(password)
	
	fmt.Printf("Strong Password Hash: %s\n", strongHash)
	
	// Verify password
	err := strongPasswordVerify(strongHash, password)
	if err != nil {
		fmt.Printf("Password verification failed: %v\n", err)
	} else {
		fmt.Printf("Password verification successful\n")
	}
}

func exampleStrongSignatureUsage() {
	// This would require actual key generation
	fmt.Println("Strong signature examples would require actual keys")
}

func exampleStrongCipherModeUsage() {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	
	plaintext := []byte("sensitive data")
	
	// Strong cipher mode usage
	gcmCipher, _ := strongAESGCMEncrypt(key, plaintext)
	cbcCipher, _ := strongAESCBCEncrypt(key, plaintext)
	
	fmt.Printf("AES-GCM: %x\n", gcmCipher)
	fmt.Printf("AES-CBC: %x\n", cbcCipher)
}

func exampleStrongHMACUsage() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	
	data := []byte("sensitive data")
	
	// Strong HMAC usage
	strongHMACSHA256 := strongHMACSHA256(key, data)
	strongHMACSHA512 := strongHMACSHA512(key, data)
	
	fmt.Printf("Strong HMAC SHA-256: %x\n", strongHMACSHA256)
	fmt.Printf("Strong HMAC SHA-512: %x\n", strongHMACSHA512)
}

func exampleStrongCertificateUsage() {
	// Strong certificate usage
	strongCertSHA256 := strongCertificateSHA256()
	strongCertSHA512 := strongCertificateSHA512()
	
	fmt.Printf("Strong Cert SHA-256: %s\n", strongCertSHA256.Subject.CommonName)
	fmt.Printf("Strong Cert SHA-512: %s\n", strongCertSHA512.Subject.CommonName)
}

func exampleStrongTLSConfigUsage() {
	// Strong TLS config usage
	strongConfig := strongTLSConfig()
	
	fmt.Printf("Strong TLS Config: %v\n", strongConfig.CipherSuites)
}

func exampleAllStrongUsage() {
	data := []byte("sensitive data")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		return
	}
	
	password := []byte("password123")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		fmt.Printf("Error generating salt: %v\n", err)
		return
	}
	
	// All strong implementations
	strongHash := strongSHA256Hash(data)
	strongRandom, _ := strongRandomNumber()
	strongEncrypt, _ := strongAES256GCMEncrypt(key, data)
	strongKeyDerivation := strongPBKDF2KeyDerivation(password, salt)
	strongHMAC := strongHMACSHA256(key, data)
	
	fmt.Printf("Strong Hash: %s\n", strongHash)
	fmt.Printf("Strong Random: %d\n", strongRandom)
	fmt.Printf("Strong Encrypt: %x\n", strongEncrypt)
	fmt.Printf("Strong Key Derivation: %x\n", strongKeyDerivation)
	fmt.Printf("Strong HMAC: %x\n", strongHMAC)
} 