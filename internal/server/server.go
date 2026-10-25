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

// SecretsHealth is OpenBao as readiness sees it: "ok", or why not ("sealed",
// "uninitialized", "unreachable"). *openbao.Client satisfies it.
type SecretsHealth interface {
	Health(ctx context.Context) string
}

type Config struct {
	Token string
	// AgentToken is the exit node's egress agent (ADR-0015 §7). Empty means no
	// agent, and the egress list is operator-only.
	AgentToken string
	DB         Pinger
	Logger     *slog.Logger
	// Tenants serves the tenant routes. Nil leaves them answering 501, which is
	// how the API runs until its site and backends are configured.
	Tenants *tenant.Service
	// Migrated reports whether the database schema is in place. Nil means it
	// is, which is what tests that never touch a database want.
	Migrated func() bool
	// Secrets is OpenBao, for readiness. Nil means the API runs without it.
	Secrets SecretsHealth
	// SecretsLoaded reports whether the API has read what it needs from
	// OpenBao at startup. Until it has, /v1 answers 503. Nil means it has.
	SecretsLoaded func() bool
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
	if cfg.SecretsLoaded == nil {
		cfg.SecretsLoaded = func() bool { return true }
	}
	mux.HandleFunc("GET /readyz", readyz(cfg.DB, cfg.Migrated, cfg.Secrets, cfg.Logger))
	mux.HandleFunc("GET /version", versionInfo)

	if cfg.Token == "" {
		panic("server: empty operator token")
	}
	v1 := http.NewServeMux()
	if cfg.Tenants != nil {
		tenantRoutes(v1, cfg.Tenants, cfg.Logger)
	}
	v1.HandleFunc("/v1/", knownCaller(notImplemented))
	mux.Handle("/v1/", requireToken(requireMigrated(cfg.Migrated, requireSecrets(cfg.SecretsLoaded, identify(cfg.Token, cfg.AgentToken, cfg.Tenants, v1)))))

	return logRequests(cfg.Logger, mux)
}

// healthz is liveness only: the process is up and serving. It never touches the
// database, so a database outage does not get the API restarted for nothing.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz reports whether the API can do work: its database answers, its
// schema is in place, and OpenBao is open. A sealed OpenBao is not ready,
// because tenant work is refused while it is sealed (ADR-0042 §3); the body
// says which, so a deploy can tell "up, but sealed" from "not up".
func readyz(db Pinger, migrated func() bool, secrets SecretsHealth, logger *slog.Logger) http.HandlerFunc {
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
		if secrets == nil {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
			return
		}
		if state := secrets.Health(ctx); state != "ok" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":   "unavailable",
				"database": "ok",
				"openbao":  state,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok", "openbao": "ok"})
	}
}

// requireSecrets answers 503 until the API has read its backend credentials
// from OpenBao, which it waits for when it starts sealed.
func requireSecrets(loaded func() bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loaded() {
			writeUnavailable(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeUnavailable is every refusal for a sealed or unreachable OpenBao: one
// status and one message, whichever route met it.
func writeUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": tenant.ErrSecretsUnavailable.Error()})
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
