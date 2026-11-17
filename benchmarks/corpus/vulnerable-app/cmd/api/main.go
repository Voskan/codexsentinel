// Command api serves the order service.
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"example.com/vulnerable-app/internal/handler"
	"example.com/vulnerable-app/internal/repo"
	"example.com/vulnerable-app/internal/service"
)

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	svc := service.New(repo.New(db), db)
	h := handler.New(svc, "/srv/files", os.Getenv("ADMIN_API_KEY"))
	srv := &http.Server{Addr: ":8080", Handler: h.Routes()}
	log.Fatal(srv.ListenAndServe())
}
