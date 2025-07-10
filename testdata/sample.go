package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // This should be hashed
}

// Database represents a database connection
type Database struct {
	conn *sql.DB
}

// NewDatabase creates a new database connection
func NewDatabase(dsn string) (*Database, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return &Database{conn: db}, nil
}

// GetUser retrieves a user by ID (vulnerable to SQL injection)
func (db *Database) GetUser(id string) (*User, error) {
	query := fmt.Sprintf("SELECT id, username, email, password FROM users WHERE id = %s", id)
	row := db.conn.QueryRow(query)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserSafe retrieves a user by ID (safe version)
func (db *Database) GetUserSafe(id string) (*User, error) {
	query := "SELECT id, username, email, password FROM users WHERE id = ?"
	row := db.conn.QueryRow(query, id)
	
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ExecuteCommand executes a system command (vulnerable to command injection)
func ExecuteCommand(cmd string) (string, error) {
	output, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ExecuteCommandSafe executes a system command safely
func ExecuteCommandSafe(cmd string, args []string) (string, error) {
	output, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ProcessUserInput processes user input (vulnerable to various attacks)
func ProcessUserInput(input string) string {
	// Vulnerable to format string attacks
	result := fmt.Sprintf(input)
	
	// Vulnerable to path traversal
	filePath := "/tmp/" + input
	file, err := os.Open(filePath)
	if err == nil {
		defer file.Close()
	}
	
	return result
}

// ComplexFunction demonstrates high complexity
func ComplexFunction(a, b, c, d, e, f, g, h, i, j int) int {
	result := 0
	
	if a > 0 {
		if b > 0 {
			if c > 0 {
				if d > 0 {
					if e > 0 {
						if f > 0 {
							if g > 0 {
								if h > 0 {
									if i > 0 {
										if j > 0 {
											result = a + b + c + d + e + f + g + h + i + j
										} else {
											result = a + b + c + d + e + f + g + h + i
										}
									} else {
										result = a + b + c + d + e + f + g + h
									}
								} else {
									result = a + b + c + d + e + f + g
								}
							} else {
								result = a + b + c + d + e + f
							}
						} else {
							result = a + b + c + d + e
						}
					} else {
						result = a + b + c + d
					}
				} else {
					result = a + b + c
				}
			} else {
				result = a + b
			}
		} else {
			result = a
		}
	} else {
		result = 0
	}
	
	return result
}

// DuplicateFunction demonstrates code duplication
func DuplicateFunction1(input string) string {
	result := strings.ToUpper(input)
	result = strings.TrimSpace(result)
	result = strings.ReplaceAll(result, " ", "_")
	return result
}

func DuplicateFunction2(input string) string {
	result := strings.ToUpper(input)
	result = strings.TrimSpace(result)
	result = strings.ReplaceAll(result, " ", "_")
	return result
}

func DuplicateFunction3(input string) string {
	result := strings.ToUpper(input)
	result = strings.TrimSpace(result)
	result = strings.ReplaceAll(result, " ", "_")
	return result
}

func main() {
	db, err := NewDatabase("user:pass@tcp(localhost:3306)/db")
	if err != nil {
		fmt.Println("Failed to connect to database")
		return
	}
	
	// Vulnerable usage
	user, err := db.GetUser("1 OR 1=1")
	if err != nil {
		fmt.Println("Error getting user")
		return
	}
	
	// Safe usage
	user, err = db.GetUserSafe("1")
	if err != nil {
		fmt.Println("Error getting user")
		return
	}
	
	fmt.Printf("User: %+v\n", user)
} 