// Package model holds the stored records and the request types.
package model

import "log/slog"

// User is a stored user. The password hash is never serialized.
type User struct {
	ID           int64  `json:"id" db:"id"`
	Email        string `json:"email" db:"email"`
	PasswordHash string `json:"-" db:"password_hash"`
}

// Account is a stored account; IsAdmin is changed only by administrators.
type Account struct {
	ID      int64  `db:"id"`
	Name    string `db:"name"`
	IsAdmin bool   `db:"is_admin"`
}

// UpdateProfileRequest is what a user may change about their account.
type UpdateProfileRequest struct {
	Name string `json:"name"`
}

// Credentials are submitted at login.
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LogValue keeps the password out of logs.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(slog.String("email", c.Email), slog.String("password", "[REDACTED]"))
}
