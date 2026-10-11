package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Server certificates for tenants' own services (ADR-0037, CHG-0047).
//
// Nothing here is sealed: see 0010_certificates.sql. A certificate is public
// and its key was never here.

const certificateColumns = `tenant, name, names, key_fingerprint, serial,
	not_before, not_after, certificate, chain, created_at, updated_at`

func scanCertificate(row pgx.Row) (tenant.Certificate, error) {
	var c tenant.Certificate
	var names []byte
	err := row.Scan(&c.Tenant, &c.Name, &names, &c.KeyFingerprint, &c.Serial,
		&c.NotBefore, &c.NotAfter, &c.PEM, &c.Chain, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return tenant.Certificate{}, err
	}
	// Stored and compared in UTC: a certificate's dates are instants, and the
	// registry should not hand back the server's idea of a zone.
	c.NotBefore, c.NotAfter = c.NotBefore.UTC(), c.NotAfter.UTC()
	return c, json.Unmarshal(names, &c.Names)
}

// PutCertificate records the certificate now current for a name, replacing
// the one before it. created_at stays the first issue's; updated_at is this
// one's.
func (p *Postgres) PutCertificate(ctx context.Context, c tenant.Certificate) (tenant.Certificate, error) {
	names, err := json.Marshal(c.Names)
	if err != nil {
		return tenant.Certificate{}, err
	}
	var out tenant.Certificate
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, c.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanCertificate(tx.QueryRow(ctx,
			`INSERT INTO tenant_certificates
			        (tenant, name, names, key_fingerprint, serial, not_before, not_after, certificate, chain)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (tenant, name) DO UPDATE
			        SET names = EXCLUDED.names,
			            key_fingerprint = EXCLUDED.key_fingerprint,
			            serial = EXCLUDED.serial,
			            not_before = EXCLUDED.not_before,
			            not_after = EXCLUDED.not_after,
			            certificate = EXCLUDED.certificate,
			            chain = EXCLUDED.chain,
			            updated_at = now()
			 RETURNING `+certificateColumns,
			c.Tenant, c.Name, names, c.KeyFingerprint, c.Serial, c.NotBefore, c.NotAfter, c.PEM, c.Chain))
		return err
	})
	if err != nil {
		return tenant.Certificate{}, err
	}
	return out, nil
}

func (p *Postgres) GetCertificate(ctx context.Context, tenantName, name string) (tenant.Certificate, error) {
	c, err := scanCertificate(p.pool.QueryRow(ctx,
		`SELECT `+certificateColumns+` FROM tenant_certificates WHERE tenant = $1 AND name = $2`,
		tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Certificate{}, tenant.ErrNotFound
	}
	return c, err
}

func (p *Postgres) ListCertificates(ctx context.Context, tenantName string) ([]tenant.Certificate, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+certificateColumns+` FROM tenant_certificates WHERE tenant = $1 ORDER BY name`,
		tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCertificate removes the row. A row that is not there is not an error,
// so a repeated delete converges.
func (p *Postgres) DeleteCertificate(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM tenant_certificates WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}
