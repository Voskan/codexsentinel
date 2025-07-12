package testdata

import (
	"database/sql"
	"fmt"
)

// BAD: Missing access control - sensitive operation without auth
func deleteUser(userID string) error {
	// VULNERABILITY: No authentication/authorization check
	db, _ := sql.Open("mysql", "dsn")
	query := "DELETE FROM users WHERE id = ?"
	_, err := db.Exec(query, userID)
	return err
}

// BAD: Direct database access without proper authorization
func updateUserCredentials(userID string, password string) error {
	// VULNERABILITY: Direct database access without auth check
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE users SET password = ? WHERE id = ?"
	_, err := db.Exec(query, password, userID)
	return err
}

// BAD: Admin function without proper access control
func adminOperation(userID string) {
	// VULNERABILITY: Admin operation without role check
	fmt.Printf("Performing admin operation for user: %s\n", userID)
}

// BAD: Privileged operation without validation
func privilegedFunction(data string) {
	// VULNERABILITY: Privileged operation without proper checks
	fmt.Printf("Processing sensitive data: %s\n", data)
}

// GOOD: Function with proper access control
func safeDeleteUser(userID string, authToken string) error {
	// Safe: Check authentication first
	if !isAuthenticated(authToken) {
		return fmt.Errorf("unauthorized")
	}
	
	// Safe: Check authorization
	if !hasPermission(authToken, "delete_user") {
		return fmt.Errorf("insufficient permissions")
	}
	
	db, _ := sql.Open("mysql", "dsn")
	query := "DELETE FROM users WHERE id = ?"
	_, err := db.Exec(query, userID)
	return err
}

// Helper functions for safe example
func isAuthenticated(token string) bool {
	// Implementation would check token validity
	return len(token) > 0
}

func hasPermission(token string, permission string) bool {
	// Implementation would check user permissions
	return true
} 