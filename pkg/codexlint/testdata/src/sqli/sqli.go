package sqli

import (
	"database/sql"
	"net/http"
)

func Search(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		db.Query("SELECT * FROM items WHERE name = '" + name + "'") // want `SQL statement is built from non-constant text`
	}
}

func Reviewed(db *sql.DB, column string) {
	db.Query("SELECT " + column + " FROM items") //codex:ignore sql-injection -- column comes from an allow-list
}

func Safe(db *sql.DB, id string) {
	db.Query("SELECT * FROM items WHERE id = $1", id)
}
