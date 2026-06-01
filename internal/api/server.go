// Package api exposes the bridge HTTP surface. The bridge runs on
// the user's local machine — typically `127.0.0.1:7766` — and the
// PodMaker SaaS web app fetches against it from the browser.
//
// Security posture (dev / per-user host):
//   - bind to loopback only
//   - CORS allow only the SaaS origins listed in `AllowedOrigins`
//   - optional bearer token (`Authorization: Bearer <token>`) for the
//     write endpoints (exec, etc.) — defaults off, can be enabled by
//     setting `PODMAKER_BRIDGE_TOKEN`
//
// We deliberately do NOT support TLS — loopback only, browsers treat
// http://127.0.0.1 as a secure origin for CORS preflight.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"podmaker.sh/apps/podmaker-bridge/internal/awsvault"
)

// Config holds the configurable bits of the server.
type Config struct {
	AllowedOrigins []string
	BearerToken    string
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func New(cfg Config) *Server {
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.cors(s.mux) }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/sources", s.handleSources)
	s.mux.HandleFunc("/v1/aws-vault/profiles", s.requireAuth(s.handleAwsVaultProfiles))
	s.mux.HandleFunc("/v1/aws-vault/exec", s.requireAuth(s.handleAwsVaultExec))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "podmaker-bridge"})
}

func (s *Server) handleSources(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"sources": []map[string]any{
			{
				"slug":      "aws-vault",
				"label":     "aws-vault (99designs)",
				"available": awsvault.Available(),
				"endpoints": map[string]string{
					"list": "/v1/aws-vault/profiles",
					"exec": "/v1/aws-vault/exec",
				},
			},
		},
	})
}

func (s *Server) handleAwsVaultProfiles(w http.ResponseWriter, _ *http.Request) {
	if !awsvault.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "aws-vault binary not found on PATH",
		})
		return
	}
	profiles, err := awsvault.ListProfiles()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleAwsVaultExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "json body required: {\"profile\":\"name\"}"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	creds, _, err := awsvault.Exec(ctx, body.Profile)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BearerToken == "" {
			next(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		expect := "Bearer " + s.cfg.BearerToken
		if header != expect {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer token required"})
			return
		}
		next(w, r)
	}
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "300")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.AllowedOrigins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		// Best-effort — log to stderr would require a logger we
		// haven't wired here; the parent main.go logs request
		// errors at the http.Server level.
		_ = err
	}
}
