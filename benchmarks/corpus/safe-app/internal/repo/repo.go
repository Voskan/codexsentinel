// Package repo stores users and accounts in SQL.
package repo

import (
	"context"
	"database/sql"
	"errors"

	"example.com/safe-app/internal/model"
)

// Repo is the SQL store.
type Repo struct{ db *sql.DB }

// New returns a store on db.
func New(db *sql.DB) *Repo { return &Repo{db: db} }

// sortColumns lists the columns users may sort by.
var sortColumns = map[string]string{"email": "email", "created": "created_at"}

// FindByStatus returns the users with a status, sorted by an allowed column.
func (r *Repo) FindByStatus(ctx context.Context, status, sortBy string) ([]model.User, error) {
	column, ok := sortColumns[sortBy]
	if !ok {
		return nil, errors.New("unknown sort column")
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id, email FROM users WHERE status = $1 ORDER BY "+column, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UserByID returns one user.
func (r *Repo) UserByID(ctx context.Context, id int64) (model.User, error) {
	var u model.User
	err := r.db.QueryRowContext(ctx, "SELECT id, email, password_hash FROM users WHERE id = $1", id).
		Scan(&u.ID, &u.Email, &u.PasswordHash)
	return u, err
}

// UpdateName changes the name of an account.
func (r *Repo) UpdateName(ctx context.Context, id int64, name string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE accounts SET name = $1 WHERE id = $2", name, id)
	return err
}
