// Command deevnet-api serves the Deevnet API (ADR-0012, ADR-0015).
//
// Configuration is environment only, so the container carries no config file:
//
//	DEEVNET_API_TOKEN   operator bearer token for /v1 (required; the API refuses to start without it)
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

	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	w, err := tenantService(startCtx, os.Getenv)
	cancel()
	if err != nil {
		return err
	}
	tenants := w.tenants
	reg := store.New(pool)
	if w.sealer != nil {
		reg.WithSealer(w.sealer)
	}
	if w.tenants != nil {
		reg.WithSite(w.site)
	}
	if tenants != nil {
		tenants.Store = reg
		tenants.Logger = logger
		logger.Info("serving tenants", "site", tenants.Site.Name,
			"enrollment", tenants.Enroller != nil, "secrets_sealed", w.sealer != nil)
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

	srv := &http.Server{
		Addr: addr,
		Handler: server.New(server.Config{
			Token:    token,
			DB:       pool,
			Logger:   logger,
			Tenants:  tenants,
			Migrated: migrated.Load,
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
