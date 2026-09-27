package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant Wi-Fi keys (ADR-0012 §3).
//
// Unlike workloads these allocate nothing, so none of this takes the allocation
// lock: a key's identity is the name the tenant chose.

const wifiKeyColumns = `tenant, name, trust_class, psk, mac, status, created_at, updated_at`

func scanWiFiKey(row pgx.Row) (tenant.WiFiKey, error) {
	var k tenant.WiFiKey
	var status string
	err := row.Scan(&k.Tenant, &k.Name, &k.TrustClass, &k.PSK, &k.MAC, &status, &k.CreatedAt, &k.UpdatedAt)
	k.Status = tenant.Status(status)
	return k, err
}

// PutWiFiKey inserts a key, or updates the PSK and status of one that exists.
// The trust class is fixed at creation: moving a key between classes would move
// every device holding it onto another VLAN, so the service refuses it before
// this is reached.
func (p *Postgres) PutWiFiKey(ctx context.Context, k tenant.WiFiKey) (tenant.WiFiKey, error) {
	psk, err := p.sealOne(ctx, k.PSK)
	if err != nil {
		return tenant.WiFiKey{}, err
	}
	var out tenant.WiFiKey
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// A key for a name the registry does not hold is a missing tenant, which
		// the caller can act on, rather than a foreign-key violation, which it
		// cannot. CreateWorkload resolves the tenant the same way.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, k.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanWiFiKey(tx.QueryRow(ctx,
			`INSERT INTO tenant_wifi_keys (tenant, name, trust_class, psk, mac, status)
			      VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (tenant, name) DO UPDATE
			         SET psk = EXCLUDED.psk, mac = EXCLUDED.mac, status = EXCLUDED.status, updated_at = now()
			   RETURNING `+wifiKeyColumns,
			k.Tenant, k.Name, k.TrustClass, psk, k.MAC, string(k.Status)))
		return err
	})
	if err != nil {
		return tenant.WiFiKey{}, err
	}
	// Hand back what the caller gave us, not what we sealed.
	out.PSK = k.PSK
	return out, nil
}

// GetWiFiKey returns one key. A PSK that will not open comes back empty with
// Unreadable set, exactly as a tenant's other secrets do.
func (p *Postgres) GetWiFiKey(ctx context.Context, tenantName, name string) (tenant.WiFiKey, error) {
	k, err := scanWiFiKey(p.pool.QueryRow(ctx,
		`SELECT `+wifiKeyColumns+` FROM tenant_wifi_keys WHERE tenant = $1 AND name = $2`, tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.WiFiKey{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.WiFiKey{}, err
	}
	return p.openWiFiKey(ctx, k), nil
}

// ListWiFiKeys returns a tenant's keys, oldest first.
func (p *Postgres) ListWiFiKeys(ctx context.Context, tenantName string) ([]tenant.WiFiKey, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+wifiKeyColumns+` FROM tenant_wifi_keys WHERE tenant = $1 ORDER BY created_at, name`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.WiFiKey
	for rows.Next() {
		k, err := scanWiFiKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p.openWiFiKey(ctx, k))
	}
	return out, rows.Err()
}

func (p *Postgres) SetWiFiKeyStatus(ctx context.Context, tenantName, name string, status tenant.Status) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE tenant_wifi_keys SET status = $3, updated_at = now() WHERE tenant = $1 AND name = $2`,
		tenantName, name, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// DeleteWiFiKey removes the row. A key that is not there is not an error, so a
// repeated delete converges.
func (p *Postgres) DeleteWiFiKey(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM tenant_wifi_keys WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}

func (p *Postgres) sealOne(ctx context.Context, plaintext string) (string, error) {
	if p.sealer == nil {
		return plaintext, nil
	}
	return p.sealer.Seal(ctx, plaintext)
}

func (p *Postgres) openWiFiKey(ctx context.Context, k tenant.WiFiKey) tenant.WiFiKey {
	if p.sealer == nil {
		return k
	}
	k.PSK, k.Unreadable = p.openOne(ctx, k.PSK, "wifi-key")
	return k
}

// PutAdmissionKey stores the key issued with an admission, replacing an
// earlier one for the same name (ADR-0029 §1).
func (p *Postgres) PutAdmissionKey(ctx context.Context, k tenant.AdmissionKey) error {
	psk, err := p.sealOne(ctx, k.PSK)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO admission_keys (tenant, psk, mac) VALUES ($1, $2, $3)
		 ON CONFLICT (tenant) DO UPDATE SET psk = EXCLUDED.psk, mac = EXCLUDED.mac, created_at = now()`,
		k.Tenant, psk, k.MAC)
	return err
}

// GetAdmissionKey returns the key an admission issued for name.
func (p *Postgres) GetAdmissionKey(ctx context.Context, name string) (tenant.AdmissionKey, error) {
	var k tenant.AdmissionKey
	err := p.pool.QueryRow(ctx,
		`SELECT tenant, psk, mac, created_at FROM admission_keys WHERE tenant = $1`, name).
		Scan(&k.Tenant, &k.PSK, &k.MAC, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.AdmissionKey{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.AdmissionKey{}, err
	}
	if p.sealer != nil {
		k.PSK, k.Unreadable = p.openOne(ctx, k.PSK, "admission-key")
	}
	return k, nil
}

// DeleteAdmissionKey removes it. One that is not there is not an error.
func (p *Postgres) DeleteAdmissionKey(ctx context.Context, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM admission_keys WHERE tenant = $1`, name)
	return err
}
