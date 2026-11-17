// Package model holds the stored records.
package model

// User is a stored user.
type User struct {
	ID           int64  `db:"id"`
	Email        string `db:"email"`
	PasswordHash string `db:"password_hash"`
}

// Account is a stored account; IsAdmin grants administrator rights.
type Account struct {
	ID      int64  `json:"id" db:"id"`
	Name    string `json:"name" db:"name"`
	IsAdmin bool   `json:"is_admin" db:"is_admin"`
}

// Credentials are submitted at login.
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
