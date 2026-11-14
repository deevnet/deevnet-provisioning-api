package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant runtime secrets (ADR-0021, CHG-0067): paths, versions and readers.
// Never a value - see 0013_tenant_secrets.sql.

const runtimeSecretColumns = `tenant, path, version, created_at, updated_at`

func scanRuntimeSecret(row pgx.Row) (tenant.RuntimeSecret, error) {
	var s tenant.RuntimeSecret
	err := row.Scan(&s.Tenant, &s.Path, &s.Version, &s.CreatedAt, &s.UpdatedAt)
	return s, err
}

// PutRuntimeSecret records a secret's path and version, or updates the
// version of one already recorded.
func (p *Postgres) PutRuntimeSecret(ctx context.Context, sec tenant.RuntimeSecret) (tenant.RuntimeSecret, error) {
	out, err := scanRuntimeSecret(p.pool.QueryRow(ctx,
		`INSERT INTO tenant_runtime_secrets (tenant, path, version)
		 SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM tenants WHERE name = $1)
		 ON CONFLICT (tenant, path) DO UPDATE
		        SET version = EXCLUDED.version, updated_at = now()
		 RETURNING `+runtimeSecretColumns,
		sec.Tenant, sec.Path, sec.Version))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.RuntimeSecret{}, tenant.ErrNotFound
	}
	return out, err
}

func (p *Postgres) GetRuntimeSecret(ctx context.Context, tenantName, path string) (tenant.RuntimeSecret, error) {
	s, err := scanRuntimeSecret(p.pool.QueryRow(ctx,
		`SELECT `+runtimeSecretColumns+` FROM tenant_runtime_secrets WHERE tenant = $1 AND path = $2`,
		tenantName, path))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.RuntimeSecret{}, tenant.ErrNotFound
	}
	return s, err
}

// DeleteRuntimeSecret removes the row. One that is not there is not an error.
func (p *Postgres) DeleteRuntimeSecret(ctx context.Context, tenantName, path string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM tenant_runtime_secrets WHERE tenant = $1 AND path = $2`, tenantName, path)
	return err
}

const secretReaderColumns = `tenant, name, workload, paths, created_at, updated_at`

func scanSecretReader(row pgx.Row) (tenant.SecretReader, error) {
	var r tenant.SecretReader
	var paths []byte
	if err := row.Scan(&r.Tenant, &r.Name, &r.Workload, &paths, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return tenant.SecretReader{}, err
	}
	return r, json.Unmarshal(paths, &r.Paths)
}

// PutSecretReader records a reader, or replaces the workload and paths of
// one already recorded.
func (p *Postgres) PutSecretReader(ctx context.Context, r tenant.SecretReader) (tenant.SecretReader, error) {
	paths, err := json.Marshal(r.Paths)
	if err != nil {
		return tenant.SecretReader{}, err
	}
	out, err := scanSecretReader(p.pool.QueryRow(ctx,
		`INSERT INTO tenant_secret_readers (tenant, name, workload, paths)
		 SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM tenants WHERE name = $1)
		 ON CONFLICT (tenant, name) DO UPDATE
		        SET workload = EXCLUDED.workload, paths = EXCLUDED.paths, updated_at = now()
		 RETURNING `+secretReaderColumns,
		r.Tenant, r.Name, r.Workload, paths))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.SecretReader{}, tenant.ErrNotFound
	}
	return out, err
}

func (p *Postgres) GetSecretReader(ctx context.Context, tenantName, name string) (tenant.SecretReader, error) {
	r, err := scanSecretReader(p.pool.QueryRow(ctx,
		`SELECT `+secretReaderColumns+` FROM tenant_secret_readers WHERE tenant = $1 AND name = $2`,
		tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.SecretReader{}, tenant.ErrNotFound
	}
	return r, err
}

func (p *Postgres) ListSecretReaders(ctx context.Context, tenantName string) ([]tenant.SecretReader, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+secretReaderColumns+` FROM tenant_secret_readers WHERE tenant = $1 ORDER BY name`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.SecretReader
	for rows.Next() {
		r, err := scanSecretReader(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteSecretReader removes the row. One that is not there is not an error.
func (p *Postgres) DeleteSecretReader(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM tenant_secret_readers WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}
