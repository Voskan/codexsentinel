package testdata

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"runtime/debug"
)

// BAD: Debug endpoint exposed in production
func debugHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Debug endpoint exposed
	fmt.Fprintf(w, "Debug info: %s", debug.Stack())
}

// BAD: Health check endpoint with sensitive info
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Exposing system information
	fmt.Fprintf(w, "Status: OK\nVersion: 1.0.0\nConfig: %s", "sensitive-config")
}

// BAD: Admin endpoint without proper auth
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Admin endpoint without authentication
	fmt.Fprintf(w, "Admin panel: %s", "admin-data")
}

// BAD: Metrics endpoint exposing sensitive data
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Exposing internal metrics
	fmt.Fprintf(w, "Metrics: %s", "internal-metrics")
}

// BAD: CORS with wildcard origin
func setupCORS() {
	// VULNERABILITY: Unsafe CORS configuration
	cors := map[string]string{
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Credentials": "true",
	}
	_ = cors
}

// BAD: Debug mode enabled in production
func setupDebugMode() {
	// VULNERABILITY: Debug mode enabled
	debugMode := true
	verboseErrors := true
	_ = debugMode
	_ = verboseErrors
}

// BAD: Development tools in production
func setupDevTools() {
	// VULNERABILITY: Development tools in production
	http.HandleFunc("/debug/pprof/", pprof.Index)
	http.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	http.HandleFunc("/debug/pprof/profile", pprof.Profile)
	http.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
}

// BAD: Exposed configuration
func configHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Exposing configuration
	config := map[string]string{
		"database_url": "mysql://user:pass@localhost/db",
		"api_key": "sk-1234567890abcdef",
		"secret": "super-secret-key",
	}
	fmt.Fprintf(w, "Config: %v", config)
}

// BAD: Missing security headers
func unsafeHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Missing security headers
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "Response without security headers")
}

// BAD: Verbose error messages
func errorHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Verbose error messages
	err := fmt.Errorf("Database connection failed: mysql://user:pass@localhost/db")
	fmt.Fprintf(w, "Error: %v", err)
}

// BAD: Insecure default settings
func setupDefaults() {
	// VULNERABILITY: Insecure default settings
	securityConfig := map[string]string{
		"auth": "none",
		"encryption": "basic",
		"session": "simple",
	}
	_ = securityConfig
}

// GOOD: Secure configuration
func secureHandler(w http.ResponseWriter, r *http.Request) {
	// Safe: Proper security headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	// Safe: Generic error message
	fmt.Fprintf(w, "An error occurred")
}

// GOOD: Secure CORS configuration
func setupSecureCORS() {
	// Safe: Specific allowed origins
	cors := map[string]string{
		"Access-Control-Allow-Origin": "https://trusted-domain.com",
		"Access-Control-Allow-Credentials": "false",
	}
	_ = cors
}

// GOOD: Production-ready configuration
func setupProduction() {
	// Safe: Production settings
	debugMode := false
	verboseErrors := false
	_ = debugMode
	_ = verboseErrors
} 