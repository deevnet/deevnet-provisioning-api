package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant MQTT broker accounts (ADR-0012 §3, CHG-0016).
//
// Nothing here is sealed: see 0005_broker_accounts.sql for why the hash is
// stored in the clear and why that is a guarantee rather than a gap.

const brokerColumns = `tenant, name, coalesce(device, ''), password_hash,
	publish_acl, subscribe_acl, status, created_at, updated_at`

func scanBrokerAccount(row pgx.Row) (tenant.BrokerAccount, error) {
	var a tenant.BrokerAccount
	var status string
	var pub, sub []byte
	err := row.Scan(&a.Tenant, &a.Name, &a.Device, &a.PasswordHash,
		&pub, &sub, &status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return tenant.BrokerAccount{}, err
	}
	a.Status = tenant.Status(status)
	if err := json.Unmarshal(pub, &a.Publish); err != nil {
		return tenant.BrokerAccount{}, err
	}
	return a, json.Unmarshal(sub, &a.Subscribe)
}

func nullableDevice(d string) any {
	if d == "" {
		return nil
	}
	return d
}

// PutBrokerAccount inserts an account or updates one that exists.
//
// The row goes down before the broker is told anything, so an account the
// broker holds is never one the registry has no record of - the same ordering
// PutWiFiKey uses, and for the same reason.
func (p *Postgres) PutBrokerAccount(ctx context.Context, a tenant.BrokerAccount) (tenant.BrokerAccount, error) {
	pub, err := json.Marshal(a.Publish)
	if err != nil {
		return tenant.BrokerAccount{}, err
	}
	sub, err := json.Marshal(a.Subscribe)
	if err != nil {
		return tenant.BrokerAccount{}, err
	}
	var out tenant.BrokerAccount
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, a.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanBrokerAccount(tx.QueryRow(ctx,
			`INSERT INTO tenant_broker_accounts
			        (tenant, name, device, password_hash, publish_acl, subscribe_acl, status)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (tenant, name) DO UPDATE
			        SET device = EXCLUDED.device,
			            password_hash = EXCLUDED.password_hash,
			            publish_acl = EXCLUDED.publish_acl,
			            subscribe_acl = EXCLUDED.subscribe_acl,
			            status = EXCLUDED.status,
			            updated_at = now()
			 RETURNING `+brokerColumns,
			a.Tenant, a.Name, nullableDevice(a.Device), a.PasswordHash, pub, sub, string(a.Status)))
		return err
	})
	if err != nil {
		return tenant.BrokerAccount{}, err
	}
	return out, nil
}

func (p *Postgres) GetBrokerAccount(ctx context.Context, tenantName, name string) (tenant.BrokerAccount, error) {
	a, err := scanBrokerAccount(p.pool.QueryRow(ctx,
		`SELECT `+brokerColumns+` FROM tenant_broker_accounts WHERE tenant = $1 AND name = $2`,
		tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.BrokerAccount{}, tenant.ErrNotFound
	}
	return a, err
}

func (p *Postgres) ListBrokerAccounts(ctx context.Context, tenantName string) ([]tenant.BrokerAccount, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+brokerColumns+` FROM tenant_broker_accounts WHERE tenant = $1 ORDER BY created_at, name`,
		tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.BrokerAccount
	for rows.Next() {
		a, err := scanBrokerAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) SetBrokerAccountStatus(ctx context.Context, tenantName, name string, status tenant.Status) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE tenant_broker_accounts SET status = $3, updated_at = now() WHERE tenant = $1 AND name = $2`,
		tenantName, name, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// DeleteBrokerAccount removes the row. A row that is not there is not an
// error, so a repeated delete converges.
func (p *Postgres) DeleteBrokerAccount(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM tenant_broker_accounts WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}
