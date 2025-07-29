package testdata

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Path Traversal safe handler - with proper path validation
func (h *PathTraversalSafeHandler) ReadFileHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: validate and sanitize file path
	filename := r.FormValue("file")
	
	// Validate path to prevent directory traversal
	if !isValidPath(filename) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	
	// Clean the path to remove any traversal attempts
	cleanPath := filepath.Clean(filename)
	
	// Ensure path is within allowed directory
	if !isPathInAllowedDirectory(cleanPath, "/var/www/uploads") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Safe file read with validated path
	data, err := ioutil.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "File content: %s", template.HTMLEscapeString(string(data)))
}

// Path Traversal safe handler - with path sanitization
func (h *SafeHandler) OpenFileHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: sanitize and validate file path
	filepath := r.FormValue("path")
	
	// Remove any path traversal sequences
	sanitizedPath := sanitizePath(filepath)
	
	// Validate path is within allowed directory
	if !isPathInAllowedDirectory(sanitizedPath, "/var/www/files") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Safe file open with sanitized path
	file, err := os.Open(sanitizedPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "File opened: %s", template.HTMLEscapeString(sanitizedPath))
}

// Path Traversal safe handler - with directory validation
func (h *SafeHandler) ListDirectoryHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: validate directory path
	dirPath := r.FormValue("directory")
	
	// Validate directory path
	if !isValidDirectoryPath(dirPath) {
		http.Error(w, "Invalid directory path", http.StatusBadRequest)
		return
	}
	
	// Clean the directory path
	cleanDirPath := filepath.Clean(dirPath)
	
	// Ensure directory is within allowed path
	if !isPathInAllowedDirectory(cleanDirPath, "/var/www/public") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Safe directory read with validated path
	_, err := ioutil.ReadDir(cleanDirPath)
	if err != nil {
		http.Error(w, "Directory not found", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "Directory listing: %s", template.HTMLEscapeString(cleanDirPath))
}

// Path Traversal safe handler - with template validation
func (h *SafeHandler) LoadTemplateHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Safe: validate template path
	templatePath := r.FormValue("template")
	
	// Validate template path
	if !isValidTemplatePath(templatePath) {
		http.Error(w, "Invalid template path", http.StatusBadRequest)
		return
	}
	
	// Clean template path
	cleanTemplatePath := filepath.Clean(templatePath)
	
	// Ensure template is within allowed directory
	if !isPathInAllowedDirectory(cleanTemplatePath, "/var/www/templates") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	// Safe template loading with validated path
	tmpl, err := template.ParseFiles(cleanTemplatePath)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	
	tmpl.Execute(w, nil)
}

// Helper functions for path validation
func isValidPath(path string) bool {
	// Check for path traversal sequences
	traversalPatterns := []string{
		"../", "..\\", "..%2f", "..%5c", "..%2F", "..%5C",
		"....//", "....\\\\", "....%2f", "....%5c",
	}
	
	pathLower := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(pathLower, pattern) {
			return false
		}
	}
	
	return true
}

func isPathInAllowedDirectory(path, allowedDir string) bool {
	// Resolve the absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	
	// Resolve the allowed directory
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return false
	}
	
	// Check if path is within allowed directory
	return strings.HasPrefix(absPath, absAllowedDir)
}

func sanitizePath(path string) string {
	// Remove any path traversal sequences
	sanitized := path
	traversalPatterns := []string{
		"../", "..\\", "..%2f", "..%5c", "..%2F", "..%5C",
		"....//", "....\\\\", "....%2f", "....%5c",
	}
	
	for _, pattern := range traversalPatterns {
		sanitized = strings.ReplaceAll(sanitized, pattern, "")
	}
	
	return filepath.Clean(sanitized)
}

func isValidDirectoryPath(path string) bool {
	// Check for directory traversal patterns
	if !isValidPath(path) {
		return false
	}
	
	// Additional directory-specific checks
	dirPatterns := []string{
		"/etc/", "/proc/", "/sys/", "/dev/", "/root/",
		"c:\\windows\\", "c:\\system32\\",
	}
	
	pathLower := strings.ToLower(path)
	for _, pattern := range dirPatterns {
		if strings.Contains(pathLower, pattern) {
			return false
		}
	}
	
	return true
}

func isValidTemplatePath(path string) bool {
	// Check for template-specific validation
	if !isValidPath(path) {
		return false
	}
	
	// Check for allowed template extensions
	allowedExtensions := []string{".html", ".htm", ".tmpl", ".template"}
	hasValidExtension := false
	
	for _, ext := range allowedExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			hasValidExtension = true
			break
		}
	}
	
	return hasValidExtension
}

// PathTraversalSafeHandler struct for HTTP handlers with Path Traversal protection
type PathTraversalSafeHandler struct {
	db *sql.DB
}

var pathTraversalSafeDB *sql.DB 