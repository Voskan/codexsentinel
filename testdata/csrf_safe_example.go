package testdata

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
)

// CSRF safe handler - with proper CSRF protection
func (h *Handler) CreateUserHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Validate CSRF token
	if !validateCSRFToken(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	
	userID := r.FormValue("user_id")
	username := r.FormValue("username")
	
	// Database write with CSRF protection
	safeDB.Exec("INSERT INTO users (id, username) VALUES (?, ?)", userID, username)
	
	// Safe output with HTML escaping
	fmt.Fprintf(w, "User created: %s", template.HTMLEscapeString(username))
}

// CSRF safe handler - with token validation
func (h *Handler) UpdateUserHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Check CSRF token
	if !validateCSRFToken(r) {
		http.Error(w, "CSRF token validation failed", http.StatusForbidden)
		return
	}
	
	userID := r.FormValue("user_id")
	newEmail := r.FormValue("email")
	
	// Database operation with CSRF protection
	safeDB.Exec("UPDATE users SET email = ? WHERE id = ?", newEmail, userID)
	
	fmt.Fprintf(w, "User updated: %s", template.HTMLEscapeString(userID))
}

// CSRF safe handler - with antiforgery token
func (h *Handler) ProcessPaymentHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Validate antiforgery token
	if !validateAntiforgeryToken(r) {
		http.Error(w, "Invalid antiforgery token", http.StatusForbidden)
		return
	}
	
	amount := r.FormValue("amount")
	accountID := r.FormValue("account_id")
	
	// Critical operation with CSRF protection
	safeDB.Exec("INSERT INTO transactions (amount, account_id) VALUES (?, ?)", amount, accountID)
	
	fmt.Fprintf(w, "Payment processed: $%s", template.HTMLEscapeString(amount))
}

// CSRF safe handler - with XSRF token
func (h *Handler) DeleteUserHandlerSafe(w http.ResponseWriter, r *http.Request) {
	// Validate XSRF token
	if !validateXSRFToken(r) {
		http.Error(w, "XSRF token validation failed", http.StatusForbidden)
		return
	}
	
	userID := r.FormValue("user_id")
	
	// Database delete with CSRF protection
	safeDB.Exec("DELETE FROM users WHERE id = ?", userID)
	
	fmt.Fprintf(w, "User deleted: %s", template.HTMLEscapeString(userID))
}

// Helper functions for CSRF protection
func validateCSRFToken(r *http.Request) bool {
	token := r.FormValue("csrf_token")
	expectedToken := getExpectedCSRFToken(r)
	return token == expectedToken
}

func validateAntiforgeryToken(r *http.Request) bool {
	token := r.FormValue("antiforgery_token")
	expectedToken := getExpectedAntiforgeryToken(r)
	return token == expectedToken
}

func validateXSRFToken(r *http.Request) bool {
	token := r.FormValue("xsrf_token")
	expectedToken := getExpectedXSRFToken(r)
	return token == expectedToken
}

func getExpectedCSRFToken(r *http.Request) string {
	// In real implementation, this would get token from session
	return "expected_csrf_token"
}

func getExpectedAntiforgeryToken(r *http.Request) string {
	// In real implementation, this would get token from session
	return "expected_antiforgery_token"
}

func getExpectedXSRFToken(r *http.Request) string {
	// In real implementation, this would get token from session
	return "expected_xsrf_token"
}

// Generate CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// SafeHandler struct for HTTP handlers with CSRF protection
type SafeHandler struct {
	db *sql.DB
}

var safeDB *sql.DB 