// Package store is the tenant registry in PostgreSQL (ADR-0015 §1).
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Advisory lock keys. Arbitrary, but fixed: every API instance must agree.
const (
	migrateLock    = 0x6465766e_0001 // "devn" 1
	allocationLock = 0x6465766e_0002
)

// Postgres is a tenant.Store.
type Postgres struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Migrate applies every embedded migration not yet recorded, in order, each in
// its own transaction, under a lock so two instances starting together do not
// race.
func (p *Postgres) Migrate(ctx context.Context) error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLock); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrateLock) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: name must start with a number", base)
		}
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", base, err)
		}
	}
	return nil
}

const tenantColumns = `name, idx, status, tsig_secret, state_secret, api_token_hash, created_at, updated_at`

func scanTenant(row pgx.Row) (tenant.Record, error) {
	var r tenant.Record
	var status string
	err := row.Scan(&r.Name, &r.Index, &status, &r.Secrets.TSIG, &r.Secrets.State, &r.Secrets.APITokenHash, &r.CreatedAt, &r.UpdatedAt)
	r.Status = tenant.Status(status)
	return r, err
}

func (p *Postgres) Get(ctx context.Context, name string) (tenant.Record, error) {
	r, err := scanTenant(p.pool.QueryRow(ctx, `SELECT `+tenantColumns+` FROM tenants WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Record{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.Record{}, err
	}
	rows, err := p.pool.Query(ctx, `SELECT step, ok, COALESCE(error, ''), updated_at FROM tenant_steps WHERE tenant = $1 ORDER BY updated_at, step`, name)
	if err != nil {
		return tenant.Record{}, err
	}
	r.Steps, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.Step, error) {
		var s tenant.Step
		err := row.Scan(&s.Name, &s.OK, &s.Error, &s.UpdatedAt)
		return s, err
	})
	return r, err
}

func (p *Postgres) List(ctx context.Context) ([]tenant.Record, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+tenantColumns+` FROM tenants ORDER BY idx`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.Record, error) { return scanTenant(row) })
}

func (p *Postgres) Create(ctx context.Context, name string, secrets tenant.Secrets, pick func(map[int]string) (int, error)) (tenant.Record, error) {
	var rec tenant.Record
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Held until the transaction ends: allocation is serialised across every
		// API instance, and the UNIQUE constraint is the backstop.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, allocationLock); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT idx, name FROM tenants`)
		if err != nil {
			return err
		}
		held := map[int]string{}
		var idx int
		var holder string
		_, err = pgx.ForEachRow(rows, []any{&idx, &holder}, func() error {
			held[idx] = holder
			return nil
		})
		if err != nil {
			return err
		}
		for _, h := range held {
			if h == name {
				return tenant.ErrExists
			}
		}

		n, err := pick(held)
		if err != nil {
			return err
		}
		rec, err = scanTenant(tx.QueryRow(ctx,
			`INSERT INTO tenants (name, idx, status, tsig_secret, state_secret, api_token_hash)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 RETURNING `+tenantColumns,
			name, n, string(tenant.StatusProvisioning), secrets.TSIG, secrets.State, secrets.APITokenHash))
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "tenants_pkey" {
		return tenant.Record{}, tenant.ErrExists
	}
	return rec, err
}

func (p *Postgres) SetStatus(ctx context.Context, name string, status tenant.Status) error {
	return p.execOne(ctx, `UPDATE tenants SET status = $2, updated_at = now() WHERE name = $1`, name, string(status))
}

func (p *Postgres) SetSecrets(ctx context.Context, name string, s tenant.Secrets) error {
	return p.execOne(ctx,
		`UPDATE tenants SET tsig_secret = $2, state_secret = $3, api_token_hash = $4, updated_at = now() WHERE name = $1`,
		name, s.TSIG, s.State, s.APITokenHash)
}

func (p *Postgres) RecordStep(ctx context.Context, name, step string, stepErr error) error {
	var msg *string
	if stepErr != nil {
		m := stepErr.Error()
		msg = &m
	}
	_, err := p.pool.Exec(ctx,
		`INSERT INTO tenant_steps (tenant, step, ok, error) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant, step) DO UPDATE SET ok = EXCLUDED.ok, error = EXCLUDED.error, updated_at = now()`,
		name, step, stepErr == nil, msg)
	return err
}

func (p *Postgres) Delete(ctx context.Context, name string) error {
	return p.execOne(ctx, `DELETE FROM tenants WHERE name = $1`, name)
}

func (p *Postgres) Audit(ctx context.Context, e tenant.AuditEntry) error {
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO audit_log (actor, action, tenant, detail) VALUES ($1, $2, $3, $4)`,
		e.Actor, e.Action, e.Tenant, raw)
	return err
}

func (p *Postgres) execOne(ctx context.Context, sql string, args ...any) error {
	tag, err := p.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}
