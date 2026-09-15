// Command deevnet-api serves the Deevnet API (ADR-0012).
//
// Configuration is environment only, so the container carries no config file:
//
//	DEEVNET_API_TOKEN   bearer token for /v1 (required; the API refuses to start without it)
//	DATABASE_URL        PostgreSQL connection string (required)
//	DEEVNET_API_LISTEN  listen address (default ":8080")
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/deevnet/deevnet-provisioning-api/internal/server"
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

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.New(server.Config{Token: token, DB: pool, Logger: logger}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr, "version", version.Version, "commit", version.Commit)
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
