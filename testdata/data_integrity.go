package testdata

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// BAD: File operation without integrity checks
func downloadFile(url string) error {
	// VULNERABILITY: Downloading file without integrity verification
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	file, err := os.Create("downloaded_file")
	if err != nil {
		return err
	}
	defer file.Close()
	
	_, err = io.Copy(file, resp.Body)
	return err
}

// BAD: Processing untrusted data without validation
func processUserInput(data []byte) {
	// VULNERABILITY: Processing untrusted data without validation
	var result map[string]interface{}
	json.Unmarshal(data, &result) // No validation before processing
	
	fmt.Printf("Processed data: %v\n", result)
}

// BAD: Critical data handler without integrity checks
func handleUserCredentials(userID string, password string) error {
	// VULNERABILITY: Handling critical data without integrity checks
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE users SET password = ? WHERE id = ?"
	_, err := db.Exec(query, password, userID)
	return err
}

// BAD: Network download without integrity verification
func fetchConfig(url string) error {
	// VULNERABILITY: Downloading configuration without integrity check
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Process downloaded config without verification
	config, _ := io.ReadAll(resp.Body)
	fmt.Printf("Config: %s\n", string(config))
	return nil
}

// GOOD: File operation with integrity checks
func secureDownloadFile(url string, expectedHash string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	// Verify integrity
	actualHash := sha256.Sum256(data)
	if fmt.Sprintf("%x", actualHash) != expectedHash {
		return fmt.Errorf("integrity check failed")
	}
	
	file, err := os.Create("secure_file")
	if err != nil {
		return err
	}
	defer file.Close()
	
	_, err = file.Write(data)
	return err
}

// GOOD: Validating untrusted data before processing
func secureProcessUserInput(data []byte) error {
	// Validate data before processing
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	
	if len(data) > 1024*1024 { // 1MB limit
		return fmt.Errorf("data too large")
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	
	// Additional validation
	if _, ok := result["required_field"]; !ok {
		return fmt.Errorf("missing required field")
	}
	
	fmt.Printf("Processed data: %v\n", result)
	return nil
}

// GOOD: Critical data handler with integrity checks
func secureHandleUserCredentials(userID string, password string, signature string) error {
	// Verify signature before processing
	if !verifySignature(password, signature) {
		return fmt.Errorf("invalid signature")
	}
	
	// Hash password for storage
	hashedPassword := hashPassword(password)
	
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE users SET password = ? WHERE id = ?"
	_, err := db.Exec(query, hashedPassword, userID)
	return err
}

// Helper functions for secure examples
func verifySignature(data string, signature string) bool {
	// Implementation would verify cryptographic signature
	return len(signature) > 0
}

func hashPassword(password string) string {
	// Implementation would hash password
	return "hashed_" + password
} 