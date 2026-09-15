// Package server is the API's HTTP surface.
//
// This is the shell ADR-0012's API grows into. It answers health, readiness and
// version, and puts every /v1 route behind the token check, where each one says
// it is not implemented yet.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-api/internal/auth"
	"github.com/deevnet/deevnet-api/internal/version"
)

// Pinger is the part of the database pool readiness needs. *pgxpool.Pool
// satisfies it; tests pass a fake.
type Pinger interface {
	Ping(ctx context.Context) error
}

type Config struct {
	Token  string
	DB     Pinger
	Logger *slog.Logger
}

func New(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /readyz", readyz(cfg.DB, cfg.Logger))
	mux.HandleFunc("GET /version", versionInfo)
	mux.Handle("/v1/", auth.Bearer(cfg.Token, http.HandlerFunc(notImplemented)))

	return logRequests(cfg.Logger, mux)
}

// healthz is liveness only: the process is up and serving. It never touches the
// database, so a database outage does not get the API restarted for nothing.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz reports whether the API can do work, which today means its database
// answers.
func readyz(db Pinger, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			// The reason is logged, not returned: readiness is unauthenticated,
			// and a connection error can name hosts and users.
			logger.Warn("readiness: database ping failed", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":   "unavailable",
				"database": "unreachable",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
	}
}

func versionInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": version.Version,
		"commit":  version.Commit,
		"built":   version.Built,
	})
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}
