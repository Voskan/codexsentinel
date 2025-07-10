package testdata

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

// InsecureSQLHandler demonstrates an unsafe SQL query vulnerable to injection.
// It is intended for testing the static analyzer's ability to detect such patterns.
func InsecureSQLHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		password := r.URL.Query().Get("password")

		// Vulnerable: unsanitized user input concatenated directly into query
		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

		rows, err := db.Query(query)
		if err != nil {
			log.Printf("query error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		if rows.Next() {
			fmt.Fprintf(w, "Welcome, %s!", username)
			return
		}

		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}
