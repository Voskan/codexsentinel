package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

// BAD: Insecure session creation
func createSession(userID string) string {
	// VULNERABILITY: Insecure session creation without proper security
	sessionID := fmt.Sprintf("session_%s_%d", userID, time.Now().Unix())
	return sessionID
}

// BAD: Insecure session validation
func validateSession(sessionID string) bool {
	// VULNERABILITY: Weak session validation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	return true
}

// BAD: Insecure session timeout
func checkSessionTimeout(sessionID string) bool {
	// VULNERABILITY: Insecure session timeout check
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return true
	}
	return false
}

// BAD: Insecure session refresh
func refreshSession(sessionID string) string {
	// VULNERABILITY: Insecure session refresh
	newSessionID := fmt.Sprintf("session_%s_%d", sessionID, time.Now().Unix())
	return newSessionID
}

// BAD: Insecure session invalidation
func invalidateSession(sessionID string) bool {
	// VULNERABILITY: Insecure session invalidation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	return true
}

// BAD: Insecure session storage
func storeSession(sessionID string, userData map[string]interface{}) error {
	// VULNERABILITY: Insecure session storage
	db, _ := sql.Open("mysql", "dsn")
	query := "INSERT INTO sessions (id, data) VALUES (?, ?)"
	_, err := db.Exec(query, sessionID, userData)
	return err
}

// BAD: Insecure session retrieval
func getSession(sessionID string) (map[string]interface{}, error) {
	// VULNERABILITY: Insecure session retrieval
	db, _ := sql.Open("mysql", "dsn")
	query := "SELECT data FROM sessions WHERE id = ?"
	row := db.QueryRow(query, sessionID)
	
	var data map[string]interface{}
	err := row.Scan(&data)
	return data, err
}

// BAD: Insecure session cookie
func setSessionCookie(w http.ResponseWriter, sessionID string) {
	// VULNERABILITY: Insecure session cookie
	cookie := &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: false, // VULNERABILITY: Should be true
		Secure:   false, // VULNERABILITY: Should be true
		SameSite: http.SameSiteNoneMode, // VULNERABILITY: Should be Strict
	}
	http.SetCookie(w, cookie)
}

// BAD: Insecure session token
func createSessionToken(userID string) string {
	// VULNERABILITY: Insecure session token creation
	token := fmt.Sprintf("token_%s_%d", userID, time.Now().Unix())
	return token
}

// BAD: Insecure JWT token
func createJWTToken(userID string) string {
	// VULNERABILITY: Insecure JWT token creation
	jwt := fmt.Sprintf("jwt_%s_%d", userID, time.Now().Unix())
	return jwt
}

// BAD: Insecure session timeout
func setSessionTimeout(sessionID string, timeout int) {
	// VULNERABILITY: Insecure session timeout setting
	if timeout == 0 || timeout == -1 {
		timeout = 3600 // Default to 1 hour
	}
	// Store timeout in database
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE sessions SET timeout = ? WHERE id = ?"
	db.Exec(query, timeout, sessionID)
}

// BAD: Insecure session expiry
func setSessionExpiry(sessionID string, expiry time.Time) {
	// VULNERABILITY: Insecure session expiry setting
	if expiry.IsZero() {
		expiry = time.Now().Add(24 * time.Hour) // Default to 24 hours
	}
	// Store expiry in database
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE sessions SET expiry = ? WHERE id = ?"
	db.Exec(query, expiry, sessionID)
}

// BAD: Insecure session lifetime
func setSessionLifetime(sessionID string, lifetime int) {
	// VULNERABILITY: Insecure session lifetime setting
	if lifetime == 0 || lifetime == -1 {
		lifetime = 86400 // Default to 24 hours
	}
	// Store lifetime in database
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE sessions SET lifetime = ? WHERE id = ?"
	db.Exec(query, lifetime, sessionID)
}

// BAD: Insecure session store
func storeSessionInCache(sessionID string, data map[string]interface{}) {
	// VULNERABILITY: Insecure session storage in cache
	cache := make(map[string]interface{})
	cache[sessionID] = data
}

// BAD: Insecure session cache
func getSessionFromCache(sessionID string) (map[string]interface{}, bool) {
	// VULNERABILITY: Insecure session retrieval from cache
	cache := make(map[string]interface{})
	data, exists := cache[sessionID]
	if !exists {
		return nil, false
	}
	return data.(map[string]interface{}), true
}

// BAD: Insecure session database
func storeSessionInDB(sessionID string, data map[string]interface{}) error {
	// VULNERABILITY: Insecure session storage in database
	db, _ := sql.Open("mysql", "dsn")
	query := "INSERT INTO sessions (id, data, created_at) VALUES (?, ?, NOW())"
	_, err := db.Exec(query, sessionID, data)
	return err
}

// BAD: Insecure session cookie handling
func getSessionFromCookie(r *http.Request) string {
	// VULNERABILITY: Insecure session retrieval from cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// BAD: Insecure session header
func getSessionFromHeader(r *http.Request) string {
	// VULNERABILITY: Insecure session retrieval from header
	sessionID := r.Header.Get("X-Session-ID")
	return sessionID
}

// BAD: Insecure session parameter
func getSessionFromParam(r *http.Request) string {
	// VULNERABILITY: Insecure session retrieval from parameter
	sessionID := r.URL.Query().Get("session")
	return sessionID
}

// BAD: Insecure login function
func loginUser(username string, password string) (string, error) {
	// VULNERABILITY: Insecure login implementation
	if username == "" || password == "" {
		return "", fmt.Errorf("invalid credentials")
	}
	
	// Create session after login
	sessionID := createSession(username)
	return sessionID, nil
}

// BAD: Insecure logout function
func logoutUser(sessionID string) error {
	// VULNERABILITY: Insecure logout implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return fmt.Errorf("invalid session")
	}
	
	// Invalidate session
	invalidateSession(sessionID)
	return nil
}

// BAD: Insecure signin function
func signinUser(username string, password string) (string, error) {
	// VULNERABILITY: Insecure signin implementation
	if username == "" || password == "" {
		return "", fmt.Errorf("invalid credentials")
	}
	
	// Create session after signin
	sessionID := createSession(username)
	return sessionID, nil
}

// BAD: Insecure signout function
func signoutUser(sessionID string) error {
	// VULNERABILITY: Insecure signout implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return fmt.Errorf("invalid session")
	}
	
	// Invalidate session
	invalidateSession(sessionID)
	return nil
}

// BAD: Insecure remember me function
func rememberUser(userID string) string {
	// VULNERABILITY: Insecure remember me implementation
	rememberToken := fmt.Sprintf("remember_%s_%d", userID, time.Now().Unix())
	return rememberToken
}

// BAD: Insecure persist user function
func persistUser(userID string) string {
	// VULNERABILITY: Insecure persist user implementation
	persistToken := fmt.Sprintf("persist_%s_%d", userID, time.Now().Unix())
	return persistToken
}

// BAD: Insecure store user function
func storeUser(userID string) string {
	// VULNERABILITY: Insecure store user implementation
	storeToken := fmt.Sprintf("store_%s_%d", userID, time.Now().Unix())
	return storeToken
}

// BAD: Insecure save user function
func saveUser(userID string) string {
	// VULNERABILITY: Insecure save user implementation
	saveToken := fmt.Sprintf("save_%s_%d", userID, time.Now().Unix())
	return saveToken
}

// BAD: Insecure expire session function
func expireSession(sessionID string) bool {
	// VULNERABILITY: Insecure expire session implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return true
	}
	return false
}

// BAD: Insecure timeout session function
func timeoutSession(sessionID string) bool {
	// VULNERABILITY: Insecure timeout session implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return true
	}
	return false
}

// BAD: Insecure refresh session function
func refreshSessionToken(sessionID string) string {
	// VULNERABILITY: Insecure refresh session implementation
	newSessionID := fmt.Sprintf("refresh_%s_%d", sessionID, time.Now().Unix())
	return newSessionID
}

// BAD: Insecure renew session function
func renewSession(sessionID string) string {
	// VULNERABILITY: Insecure renew session implementation
	newSessionID := fmt.Sprintf("renew_%s_%d", sessionID, time.Now().Unix())
	return newSessionID
}

// BAD: Insecure destroy session function
func destroySession(sessionID string) bool {
	// VULNERABILITY: Insecure destroy session implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	return true
}

// BAD: Insecure clear session function
func clearSession(sessionID string) bool {
	// VULNERABILITY: Insecure clear session implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	return true
}

// BAD: Insecure remove session function
func removeSession(sessionID string) bool {
	// VULNERABILITY: Insecure remove session implementation
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	return true
}

// BAD: Insecure session conditions
func checkSessionConditions(sessionID string) bool {
	// VULNERABILITY: Insecure session condition checks
	if sessionID == "" || sessionID == "null" || sessionID == "nil" {
		return false
	}
	if sessionID == "false" || sessionID == "0" {
		return false
	}
	if !validateSession(sessionID) {
		return false
	}
	if checkSessionTimeout(sessionID) {
		return false
	}
	return true
}

// BAD: Insecure session assignments
func setSessionValues() {
	// VULNERABILITY: Insecure session value assignments
	sessionID := ""
	sessionToken := "null"
	sessionCookie := "nil"
	sessionJWT := "false"
	sessionAuth := "0"
	
	_ = sessionID
	_ = sessionToken
	_ = sessionCookie
	_ = sessionJWT
	_ = sessionAuth
}

// BAD: Insecure session function calls
func callSessionFunctions() {
	// VULNERABILITY: Insecure session function calls
	createSession("user123")
	validateSession("session123")
	checkSessionTimeout("session123")
	refreshSession("session123")
	invalidateSession("session123")
	storeSession("session123", nil)
	getSession("session123")
	setSessionCookie(nil, "session123")
	createSessionToken("user123")
	createJWTToken("user123")
	setSessionTimeout("session123", 3600)
	setSessionExpiry("session123", time.Now())
	setSessionLifetime("session123", 86400)
	storeSessionInCache("session123", nil)
	getSessionFromCache("session123")
	storeSessionInDB("session123", nil)
	getSessionFromCookie(nil)
	getSessionFromHeader(nil)
	getSessionFromParam(nil)
	loginUser("user123", "password")
	logoutUser("session123")
	signinUser("user123", "password")
	signoutUser("session123")
	rememberUser("user123")
	persistUser("user123")
	storeUser("user123")
	saveUser("user123")
	expireSession("session123")
	timeoutSession("session123")
	refreshSessionToken("session123")
	renewSession("session123")
	destroySession("session123")
	clearSession("session123")
	removeSession("session123")
}

// BAD: Insecure session arguments
func callWithSessionArgs() {
	// VULNERABILITY: Insecure session arguments
	createSession("")
	validateSession("null")
	checkSessionTimeout("nil")
	refreshSession("false")
	invalidateSession("0")
	storeSession("", nil)
	getSession("null")
	setSessionCookie(nil, "nil")
	createSessionToken("")
	createJWTToken("null")
	setSessionTimeout("", 0)
	setSessionExpiry("", time.Time{})
	setSessionLifetime("", -1)
	storeSessionInCache("", nil)
	getSessionFromCache("null")
	storeSessionInDB("nil", nil)
	getSessionFromCookie(nil)
	getSessionFromHeader(nil)
	getSessionFromParam(nil)
	loginUser("", "")
	logoutUser("null")
	signinUser("nil", "")
	signoutUser("false")
	rememberUser("")
	persistUser("null")
	storeUser("nil")
	saveUser("")
	expireSession("0")
	timeoutSession("")
	refreshSessionToken("null")
	renewSession("nil")
	destroySession("false")
	clearSession("0")
	removeSession("")
}

// GOOD: Secure session management
func secureCreateSession(userID string) string {
	// Safe: Secure session creation with proper security
	if userID == "" {
		return ""
	}
	
	// Use cryptographically secure random session ID
	sessionID := generateSecureSessionID()
	return sessionID
}

// GOOD: Secure session validation
func secureValidateSession(sessionID string) bool {
	// Safe: Secure session validation
	if sessionID == "" {
		return false
	}
	
	// Validate session format and signature
	if !isValidSessionFormat(sessionID) {
		return false
	}
	
	// Check session expiration
	if isSessionExpired(sessionID) {
		return false
	}
	
	return true
}

// GOOD: Secure session timeout
func secureCheckSessionTimeout(sessionID string) bool {
	// Safe: Secure session timeout check
	if sessionID == "" {
		return true
	}
	
	// Check session timeout with proper validation
	return isSessionTimedOut(sessionID)
}

// Helper functions for secure examples
func generateSecureSessionID() string {
	// Implementation would generate cryptographically secure session ID
	return "secure_session_id"
}

func isValidSessionFormat(sessionID string) bool {
	// Implementation would validate session format
	return len(sessionID) > 0
}

func isSessionExpired(sessionID string) bool {
	// Implementation would check session expiration
	return false
}

func isSessionTimedOut(sessionID string) bool {
	// Implementation would check session timeout
	return false
}

// GOOD: Secure session handler
func secureSessionHandler(w http.ResponseWriter, r *http.Request) {
	// Safe: Secure session handling
	sessionID := getSecureSessionFromRequest(r)
	
	if !secureValidateSession(sessionID) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if secureCheckSessionTimeout(sessionID) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	
	fmt.Fprintf(w, "Session valid")
}

func getSecureSessionFromRequest(r *http.Request) string {
	// Safe: Secure session retrieval
	cookie, err := r.Cookie("secure_session")
	if err != nil {
		return ""
	}
	return cookie.Value
} 