// Command api serves the order service.
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/safe-app/internal/handler"
	"example.com/safe-app/internal/repo"
	"example.com/safe-app/internal/service"
)

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	svc := service.New(repo.New(db), db)
	h, err := handler.New(svc, "/srv/files", os.Getenv("ADMIN_API_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           http.NewCrossOriginProtection().Handler(h.Routes()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
