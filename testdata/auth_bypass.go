package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
)

// BAD: Authentication bypass function
func bypassAuth() bool {
	// VULNERABILITY: Hardcoded authentication bypass
	return true
}

// BAD: Skip authentication function
func skipAuth() bool {
	// VULNERABILITY: Authentication bypass
	return true
}

// BAD: Disable authentication function
func disableAuth() bool {
	// VULNERABILITY: Authentication bypass
	return true
}

// BAD: Admin bypass function
func adminBypass() bool {
	// VULNERABILITY: Admin authentication bypass
	return true
}

// BAD: Superuser bypass function
func superuserBypass() bool {
	// VULNERABILITY: Superuser authentication bypass
	return true
}

// BAD: Root access function
func rootAccess() bool {
	// VULNERABILITY: Root access bypass
	return true
}

// BAD: God mode function
func godMode() bool {
	// VULNERABILITY: God mode authentication bypass
	return true
}

// BAD: Debug mode authentication bypass
func debugMode() bool {
	// VULNERABILITY: Debug mode authentication bypass
	return true
}

// BAD: Test authentication bypass
func testAuth() bool {
	// VULNERABILITY: Test authentication bypass
	return true
}

// BAD: Development authentication bypass
func devAuth() bool {
	// VULNERABILITY: Development authentication bypass
	return true
}

// BAD: Temporary authentication bypass
func tempAuth() bool {
	// VULNERABILITY: Temporary authentication bypass
	return true
}

// BAD: Fake authentication bypass
func fakeAuth() bool {
	// VULNERABILITY: Fake authentication bypass
	return true
}

// BAD: Ignore authentication function
func ignoreAuth() bool {
	// VULNERABILITY: Ignore authentication bypass
	return true
}

// BAD: Override authentication function
func overrideAuth() bool {
	// VULNERABILITY: Override authentication bypass
	return true
}

// BAD: Admin skip function
func adminSkip() bool {
	// VULNERABILITY: Admin skip authentication bypass
	return true
}

// BAD: Admin disable function
func adminDisable() bool {
	// VULNERABILITY: Admin disable authentication bypass
	return true
}

// BAD: Set admin function
func setAdmin() bool {
	// VULNERABILITY: Set admin authentication bypass
	return true
}

// BAD: Set root function
func setRoot() bool {
	// VULNERABILITY: Set root authentication bypass
	return true
}

// BAD: Set superuser function
func setSuperuser() bool {
	// VULNERABILITY: Set superuser authentication bypass
	return true
}

// BAD: Force auth function
func forceAuth() bool {
	// VULNERABILITY: Force authentication bypass
	return true
}

// BAD: Authentication bypass condition
func checkAuth(userID string) bool {
	// VULNERABILITY: Hardcoded authentication bypass condition
	if userID == "admin" {
		return true
	}
	if userID == "root" {
		return true
	}
	if userID == "superuser" {
		return true
	}
	if userID == "bypass" {
		return true
	}
	if userID == "skip" {
		return true
	}
	if userID == "disable" {
		return true
	}
	if userID == "ignore" {
		return true
	}
	if userID == "override" {
		return true
	}
	if userID == "debug" {
		return true
	}
	if userID == "test" {
		return true
	}
	if userID == "dev" {
		return true
	}
	if userID == "temp" {
		return true
	}
	if userID == "fake" {
		return true
	}
	return false
}

// BAD: Authentication bypass assignment
func setAuthBypass() {
	// VULNERABILITY: Hardcoded authentication bypass assignments
	authEnabled := false
	authRequired := false
	authCheck := false
	authValidate := false
	authVerify := false
	
	// VULNERABILITY: Hardcoded authentication bypass values
	adminMode := true
	rootMode := true
	superuserMode := true
	bypassMode := true
	skipMode := true
	disableMode := true
	ignoreMode := true
	overrideMode := true
	debugMode := true
	testMode := true
	devMode := true
	tempMode := true
	fakeMode := true
	godMode := true
	masterMode := true
	
	_ = authEnabled
	_ = authRequired
	_ = authCheck
	_ = authValidate
	_ = authVerify
	_ = adminMode
	_ = rootMode
	_ = superuserMode
	_ = bypassMode
	_ = skipMode
	_ = disableMode
	_ = ignoreMode
	_ = overrideMode
	_ = debugMode
	_ = testMode
	_ = devMode
	_ = tempMode
	_ = fakeMode
	_ = godMode
	_ = masterMode
}

// BAD: Authentication bypass function calls
func callAuthBypass() {
	// VULNERABILITY: Authentication bypass function calls
	bypassAuth()
	skipAuth()
	disableAuth()
	ignoreAuth()
	overrideAuth()
	
	// VULNERABILITY: Admin bypass function calls
	adminBypass()
	adminSkip()
	adminDisable()
	
	// VULNERABILITY: Superuser bypass function calls
	superuserBypass()
	rootAccess()
	godMode()
	debugMode()
	
	// VULNERABILITY: Test bypass function calls
	testAuth()
	devAuth()
	tempAuth()
	fakeAuth()
	
	// VULNERABILITY: Set bypass function calls
	setAdmin()
	setRoot()
	setSuperuser()
	
	// VULNERABILITY: Force bypass function calls
	forceAuth()
	overrideAuth()
	fakeAuth()
}

// BAD: Authentication bypass with hardcoded arguments
func callWithBypassArgs() {
	// VULNERABILITY: Hardcoded authentication bypass arguments
	checkAuth("admin")
	checkAuth("root")
	checkAuth("superuser")
	checkAuth("bypass")
	checkAuth("skip")
	checkAuth("disable")
	checkAuth("ignore")
	checkAuth("override")
	checkAuth("debug")
	checkAuth("test")
	checkAuth("dev")
	checkAuth("temp")
	checkAuth("fake")
	checkAuth("god")
	checkAuth("master")
}

// BAD: Authentication bypass in HTTP handler
func authBypassHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABILITY: Authentication bypass in HTTP handler
	userID := r.URL.Query().Get("user_id")
	
	// VULNERABILITY: Hardcoded authentication bypass
	if userID == "admin" || userID == "root" || userID == "superuser" {
		fmt.Fprintf(w, "Access granted to: %s", userID)
		return
	}
	
	// VULNERABILITY: Authentication bypass conditions
	if userID == "bypass" || userID == "skip" || userID == "disable" {
		fmt.Fprintf(w, "Access granted to: %s", userID)
		return
	}
	
	// VULNERABILITY: More authentication bypass conditions
	if userID == "ignore" || userID == "override" || userID == "debug" {
		fmt.Fprintf(w, "Access granted to: %s", userID)
		return
	}
	
	// VULNERABILITY: Test authentication bypass conditions
	if userID == "test" || userID == "dev" || userID == "temp" || userID == "fake" {
		fmt.Fprintf(w, "Access granted to: %s", userID)
		return
	}
	
	// VULNERABILITY: God mode authentication bypass
	if userID == "god" || userID == "master" {
		fmt.Fprintf(w, "Access granted to: %s", userID)
		return
	}
	
	fmt.Fprintf(w, "Access denied")
}

// BAD: Database authentication bypass
func dbAuthBypass() {
	// VULNERABILITY: Database authentication bypass
	db, _ := sql.Open("mysql", "dsn")
	
	// VULNERABILITY: Hardcoded authentication bypass queries
	query := "SELECT * FROM users WHERE id = 'admin'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'root'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'superuser'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'bypass'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'skip'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'disable'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'ignore'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'override'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'debug'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'test'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'dev'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'temp'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'fake'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'god'"
	db.Query(query)
	
	query = "SELECT * FROM users WHERE id = 'master'"
	db.Query(query)
}

// GOOD: Proper authentication function
func properAuth(userID string, password string) bool {
	// Safe: Proper authentication implementation
	if userID == "" || password == "" {
		return false
	}
	
	// Safe: Validate user credentials
	if !validateCredentials(userID, password) {
		return false
	}
	
	// Safe: Check user permissions
	if !checkUserPermission(userID, "access") {
		return false
	}
	
	return true
}

// Helper functions for safe example
func validateCredentials(userID string, password string) bool {
	// Implementation would validate against database
	return len(userID) > 0 && len(password) > 0
}

func checkUserPermission(userID string, permission string) bool {
	// Implementation would check user permissions
	return true
}

// GOOD: Secure authentication handler
func secureAuthHandler(w http.ResponseWriter, r *http.Request) {
	// Safe: Proper authentication check
	userID := r.URL.Query().Get("user_id")
	password := r.URL.Query().Get("password")
	
	if !properAuth(userID, password) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	fmt.Fprintf(w, "Access granted to: %s", userID)
} 