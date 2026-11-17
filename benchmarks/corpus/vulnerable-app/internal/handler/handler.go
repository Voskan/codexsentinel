// Package handler exposes the service over HTTP.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"example.com/vulnerable-app/internal/model"
	"example.com/vulnerable-app/internal/service"
)

// Handler serves the API.
type Handler struct {
	svc     *service.Service
	baseDir string
	apiKey  string
}

// New returns a handler.
func New(svc *service.Service, baseDir, apiKey string) *Handler {
	return &Handler{svc: svc, baseDir: baseDir, apiKey: apiKey}
}

// Routes returns the API routes.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", h.searchUsers)
	mux.HandleFunc("GET /webhooks/check", h.checkWebhook)
	mux.HandleFunc("GET /files", h.download)
	mux.HandleFunc("GET /login", h.login)
	mux.HandleFunc("GET /me", h.me)
	mux.HandleFunc("PUT /account", h.updateAccount)
	mux.HandleFunc("GET /admin/stats", h.adminStats)
	return mux
}

func (h *Handler) searchUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.SearchUsers(r.Context(), r.URL.Query().Get("filter"))
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(len(users))
}

func (h *Handler) checkWebhook(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.PingWebhook(r.Context(), r.URL.Query().Get("url")); err != nil {
		http.Error(w, "webhook unreachable", http.StatusBadGateway)
	}
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(h.baseDir, r.URL.Query().Get("name")))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	creds := model.Credentials{Email: r.URL.Query().Get("email"), Password: r.URL.Query().Get("password")}
	slog.Info("login attempt", "creds", creds)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	user, err := h.svc.CurrentUser(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(user)
}

func (h *Handler) updateAccount(w http.ResponseWriter, r *http.Request) {
	var acc model.Account
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&acc); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.svc.SaveAccount(r.Context(), &acc); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
	}
}

func (h *Handler) adminStats(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != h.apiKey {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, _ = w.Write([]byte("ok"))
}
