package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

// BAD: Path traversal vulnerability
func readFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	
	// VULNERABILITY: Direct use of user input as file path
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	fmt.Fprintf(w, "File content: %s", data)
}

// BAD: Path traversal with environment variable
func readConfigFile() error {
	configPath := os.Getenv("CONFIG_PATH")
	
	// VULNERABILITY: Environment variable used as file path
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}
	
	fmt.Printf("Config: %s", data)
	return nil
}

// BAD: Path traversal with filepath.Join (unsafe)
func processUserFile(userInput string) error {
	baseDir := "/var/www/files"
	
	// VULNERABILITY: User input joined with base directory
	filePath := filepath.Join(baseDir, userInput)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	fmt.Printf("File content: %s", data)
	return nil
}

// GOOD: Safe file access with validation
func safeReadFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	
	// Safe: Validate and sanitize the file path
	if !isValidFilePath(filename) {
		http.Error(w, "Invalid file path", 400)
		return
	}
	
	// Safe: Use filepath.Clean and check for path traversal
	cleanPath := filepath.Clean(filename)
	if filepath.HasPrefix(cleanPath, "..") {
		http.Error(w, "Path traversal not allowed", 400)
		return
	}
	
	data, err := ioutil.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	fmt.Fprintf(w, "File content: %s", data)
}

func isValidFilePath(path string) bool {
	// Add validation logic here
	return len(path) > 0 && len(path) < 100
} 