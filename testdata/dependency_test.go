package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/http2"
	"golang.org/x/text/unicode/norm"
)

// TestDependencies demonstrates various package imports for testing
func TestDependencies() {
	// Database drivers
	_ = mysql.DSN{}
	_ = pq.Error{}
	_ = sqlite3.SQLiteConn{}

	// Web frameworks
	router := gin.Default()
	_ = router

	muxRouter := mux.NewRouter()
	_ = muxRouter

	// Testing
	assert.True(nil, true)

	// Crypto
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_ = hashedPassword

	// HTTP/2
	_ = http2.Server{}

	// Text normalization
	_ = norm.NFC

	fmt.Println("All dependencies imported successfully")
}

// VulnerableDependencies demonstrates potentially problematic dependencies
func VulnerableDependencies() {
	// These might have security issues or problematic licenses
	_ = mysql.DSN{}
	_ = sqlite3.SQLiteConn{}
	
	// Direct database access (architectural issue)
	db, _ := sql.Open("mysql", "user:pass@/dbname")
	_ = db
} 