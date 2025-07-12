package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// BAD: SQL injection via string concatenation
func getUserByID(db *sql.DB, userID string) (*User, error) {
	// VULNERABILITY: Direct string concatenation
	query := "SELECT * FROM users WHERE id = " + userID
	row := db.QueryRow(query)
	
	var user User
	err := row.Scan(&user.ID, &user.Name, &user.Email)
	return &user, err
}

// BAD: SQL injection with user input
func searchUsers(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	
	// VULNERABILITY: User input concatenated into query
	query := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", searchTerm)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()
	
	// Process results...
}

// BAD: SQL injection with environment variable
func getConfigFromDB(db *sql.DB) error {
	tableName := os.Getenv("DB_TABLE")
	
	// VULNERABILITY: Environment variable used in query
	query := "SELECT * FROM " + tableName
	_, err := db.Exec(query)
	return err
}

// GOOD: Safe SQL with prepared statements
func safeGetUserByID(db *sql.DB, userID string) (*User, error) {
	// Safe: Using prepared statement
	query := "SELECT * FROM users WHERE id = ?"
	row := db.QueryRow(query, userID)
	
	var user User
	err := row.Scan(&user.ID, &user.Name, &user.Email)
	return &user, err
}

type User struct {
	ID    int
	Name  string
	Email string
} 