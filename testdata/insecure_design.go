package testdata

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// BAD: Struct with exposed sensitive fields
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"` // VULNERABILITY: Exposed sensitive field
	Token    string `json:"token"`    // VULNERABILITY: Exposed sensitive field
	Secret   string `json:"secret"`   // VULNERABILITY: Exposed sensitive field
}

// BAD: Interface with too many methods (overly permissive)
type UserService interface {
	CreateUser()
	GetUser()
	UpdateUser()
	DeleteUser()
	AuthenticateUser()
	AuthorizeUser()
	ValidateUser()
	ProcessUser()
	HandleUser()
	ManageUser()
	AdminUser()
	SuperUser()
	RootUser()
}

// BAD: Function with too many responsibilities
func processUserData(userID string, data []byte) error {
	// Database operations
	db, _ := sql.Open("mysql", "dsn")
	query := "UPDATE users SET data = ? WHERE id = ?"
	db.Exec(query, data, userID)
	
	// File operations
	file, _ := os.Create("user_data.txt")
	file.Write(data)
	file.Close()
	
	// Network operations
	http.Get("https://api.example.com/notify")
	
	// Cryptographic operations
	hash := md5.Sum(data)
	fmt.Printf("Hash: %x\n", hash)
	
	return nil
}

// BAD: Hardcoded secrets
func initializeConfig() {
	apiKey := "sk-1234567890abcdef" // VULNERABILITY: Hardcoded secret
	password := "admin123"           // VULNERABILITY: Hardcoded secret
	secret := "super-secret-key"     // VULNERABILITY: Hardcoded secret
	
	fmt.Printf("API Key: %s\n", apiKey)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Secret: %s\n", secret)
}

// GOOD: Struct with private sensitive fields
type SecureUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	password string `json:"-"` // Safe: Private field
	token    string `json:"-"` // Safe: Private field
	secret   string `json:"-"` // Safe: Private field
}

// GOOD: Focused interface
type UserReader interface {
	GetUser(id string) (*User, error)
	GetUsers() ([]*User, error)
}

// GOOD: Function with single responsibility
func validateUserData(data []byte) error {
	// Only validation logic
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	return nil
}

// GOOD: Using environment variables for secrets
func secureConfig() {
	apiKey := os.Getenv("API_KEY")     // Safe: Environment variable
	password := os.Getenv("PASSWORD")   // Safe: Environment variable
	secret := os.Getenv("SECRET_KEY")   // Safe: Environment variable
	
	fmt.Printf("API Key: %s\n", apiKey)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Secret: %s\n", secret)
} 