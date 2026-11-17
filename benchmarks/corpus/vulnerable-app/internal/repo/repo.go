// Package repo stores users and accounts in SQL.
package repo

import (
	"context"
	"database/sql"

	"example.com/vulnerable-app/internal/model"
)

// Repo is the SQL store.
type Repo struct{ db *sql.DB }

// New returns a store on db.
func New(db *sql.DB) *Repo { return &Repo{db: db} }

// FindByFilter returns the users matching a filter expression.
func (r *Repo) FindByFilter(ctx context.Context, filter string) ([]model.User, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, email, password_hash FROM users WHERE "+filter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash); err != nil {
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

// Save stores an account.
func (r *Repo) Save(ctx context.Context, a *model.Account) error {
	_, err := r.db.ExecContext(ctx, "UPDATE accounts SET name = $1, is_admin = $2 WHERE id = $3", a.Name, a.IsAdmin, a.ID)
	return err
}
