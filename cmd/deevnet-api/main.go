// Command deevnet-api serves the Deevnet API (ADR-0012, ADR-0015).
//
// Configuration is environment only, so the container carries no config file:
//
//	DEEVNET_API_TOKEN   operator bearer token for /v1 (required; the API refuses to start without it)
//	DEEVNET_AGENT_TOKEN token for the exit node's egress agent: the VRF list only
//	DATABASE_URL        PostgreSQL connection string (required)
//	DEEVNET_API_LISTEN  listen address (default ":8080")
//	DEEVNET_API_TLS_CERT, DEEVNET_API_TLS_KEY
//	                    serve TLS with this certificate and key, issued by the
//	                    site CA (ADR-0016); both or neither
//
// Tenants are served when DEEVNET_SITE is set; config.go lists what that needs.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/deevnet/deevnet-provisioning-api/internal/server"
	"github.com/deevnet/deevnet-provisioning-api/internal/store"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/version"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	token := os.Getenv("DEEVNET_API_TOKEN")
	if token == "" {
		return errors.New("DEEVNET_API_TOKEN is empty; refusing to start an unauthenticated API")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is empty")
	}
	addr := os.Getenv("DEEVNET_API_LISTEN")
	if addr == "" {
		addr = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The pool dials lazily, so the API starts while its database is still
	// coming up and /readyz reports the gap, rather than the container
	// restart-looping until the database wins the race.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		// pgx redacts the password from its parse errors.
		return fmt.Errorf("DATABASE_URL: %w", err)
	}
	defer pool.Close()

	certFile, keyFile := os.Getenv("DEEVNET_API_TLS_CERT"), os.Getenv("DEEVNET_API_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		return errors.New("DEEVNET_API_TLS_CERT and DEEVNET_API_TLS_KEY are set together or not at all")
	}

	health, err := openbaoClient(os.Getenv)
	if err != nil {
		return err
	}
	reg := store.New(pool).WithLogger(logger)
	cfg := server.Config{
		Token:      token,
		AgentToken: os.Getenv("DEEVNET_AGENT_TOKEN"),
		DB:         pool,
		Logger:     logger,
	}
	if health != nil {
		cfg.Secrets = health
	}

	// The handler is swapped once the tenant service is built. Until then the
	// API serves readiness, and /v1 answers 503.
	var handler atomic.Pointer[http.Handler]
	serve := func(c server.Config) {
		h := server.New(c)
		handler.Store(&h)
	}
	// build reads the backend credentials from OpenBao. A sealed or
	// unreachable OpenBao is waited for (ADR-0042 §2); anything else is a
	// configuration error and stops the API, as before.
	build := func() error {
		startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		w, err := tenantService(startCtx, os.Getenv)
		if err != nil {
			return err
		}
		if w.sealer != nil {
			reg.WithSealer(w.sealer)
		}
		c := cfg
		if w.tenants != nil {
			reg.WithSite(w.site)
			w.tenants.Store = reg
			w.tenants.Logger = logger
			c.Tenants = w.tenants
			logger.Info("serving tenants", "site", w.tenants.Site.Name,
				"enrollment", w.tenants.Enroller != nil, "secrets_sealed", w.sealer != nil)
		}
		serve(c)
		return nil
	}

	// Migrations retry in the background for the same reason the pool dials
	// lazily. Until they have run, readiness says so and /v1 answers 503.
	var migrated atomic.Bool
	go func() {
		for {
			err := reg.Migrate(ctx)
			if err == nil {
				migrated.Store(true)
				logger.Info("database migrated")
				return
			}
			logger.Warn("migrating database", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()

	cfg.Migrated = migrated.Load
	switch err := build(); {
	case errors.Is(err, tenant.ErrSecretsUnavailable):
		logger.Warn("OpenBao is sealed or unreachable; waiting for it", "err", err)
		waiting := cfg
		waiting.SecretsLoaded = func() bool { return false }
		serve(waiting)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
				err := build()
				if err == nil {
					logger.Info("OpenBao opened; serving")
					return
				}
				if !errors.Is(err, tenant.ErrSecretsUnavailable) {
					logger.Error("building the tenant service", "err", err)
				}
			}
		}()
	case err != nil:
		return err
	}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			(*handler.Load()).ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr, "tls", certFile != "", "version", version.Version, "commit", version.Commit)
		if certFile != "" {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errc <- srv.ListenAndServeTLS(certFile, keyFile)
			return
		}
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
