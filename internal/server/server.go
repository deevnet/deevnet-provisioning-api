// Package server is the API's HTTP surface.
//
// It answers health, readiness and version unauthenticated, and puts every /v1
// route behind the operator token. The tenant routes (ADR-0015) are served when
// a tenant service is configured; every other /v1 route says it is not
// implemented yet.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/version"
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
	// Tenants serves the tenant routes. Nil leaves them answering 501, which is
	// how the API runs until its site and backends are configured.
	Tenants *tenant.Service
	// Migrated reports whether the database schema is in place. Nil means it
	// is, which is what tests that never touch a database want.
	Migrated func() bool
}

func New(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	if cfg.Migrated == nil {
		cfg.Migrated = func() bool { return true }
	}
	mux.HandleFunc("GET /readyz", readyz(cfg.DB, cfg.Migrated, cfg.Logger))
	mux.HandleFunc("GET /version", versionInfo)

	if cfg.Token == "" {
		panic("server: empty operator token")
	}
	v1 := http.NewServeMux()
	if cfg.Tenants != nil {
		tenantRoutes(v1, cfg.Tenants, cfg.Logger)
	}
	v1.HandleFunc("/v1/", knownCaller(notImplemented))
	mux.Handle("/v1/", requireToken(requireMigrated(cfg.Migrated, identify(cfg.Token, cfg.Tenants, v1))))

	return logRequests(cfg.Logger, mux)
}

// healthz is liveness only: the process is up and serving. It never touches the
// database, so a database outage does not get the API restarted for nothing.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz reports whether the API can do work: its database answers and its
// schema is in place.
func readyz(db Pinger, migrated func() bool, logger *slog.Logger) http.HandlerFunc {
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
		if !migrated() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":   "unavailable",
				"database": "migrating",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
	}
}

func requireMigrated(migrated func() bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !migrated() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database not migrated yet"})
			return
		}
		next.ServeHTTP(w, r)
	})
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
