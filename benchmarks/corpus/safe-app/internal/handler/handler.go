// Package handler exposes the service over HTTP.
package handler

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"example.com/safe-app/internal/model"
	"example.com/safe-app/internal/service"
)

// Handler serves the API.
type Handler struct {
	svc    *service.Service
	files  *os.Root
	apiKey []byte
}

// New returns a handler serving files from baseDir.
func New(svc *service.Service, baseDir, apiKey string) (*Handler, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, files: root, apiKey: []byte(apiKey)}, nil
}

// Routes returns the API routes.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users", h.searchUsers)
	mux.HandleFunc("GET /webhooks/check", h.checkWebhook)
	mux.HandleFunc("GET /files", h.download)
	mux.HandleFunc("POST /login", h.login)
	mux.HandleFunc("GET /me", h.me)
	mux.HandleFunc("PUT /profile", h.updateProfile)
	mux.HandleFunc("GET /admin/stats", h.adminStats)
	return mux
}

func (h *Handler) searchUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	users, err := h.svc.SearchUsers(r.Context(), q.Get("status"), q.Get("sort"))
	if err != nil {
		http.Error(w, "search failed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(users)
}

func (h *Handler) checkWebhook(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.PingWebhook(r.Context(), r.URL.Query().Get("name")); err != nil {
		http.Error(w, "webhook unreachable", http.StatusBadGateway)
	}
}

func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	f, err := h.files.Open(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var creds model.Credentials
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&creds); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	slog.Info("login attempt", "creds", creds)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	user, err := h.svc.CurrentUser(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

func (h *Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var req model.UpdateProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.svc.UpdateProfile(r.Context(), id, req); err != nil {
		http.Error(w, "save failed", http.StatusInternalServerError)
	}
}

func (h *Handler) adminStats(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), h.apiKey) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, _ = w.Write([]byte("ok"))
}
