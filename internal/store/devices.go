package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The tenant device registry (ADR-0012 §3).
//
// Like Wi-Fi keys and unlike workloads these allocate nothing, so none of this
// takes the allocation lock: a device's identity is the name the tenant chose.
// Unlike Wi-Fi keys, nothing here is sealed, because a device row carries no
// secret - see 0004_devices.sql.

const deviceColumns = `tenant, name, trust_class, coalesce(mac, ''), status, created_at, updated_at`

func scanDevice(row pgx.Row) (tenant.Device, error) {
	var d tenant.Device
	var status string
	err := row.Scan(&d.Tenant, &d.Name, &d.TrustClass, &d.MAC, &status, &d.CreatedAt, &d.UpdatedAt)
	d.Status = tenant.Status(status)
	return d, err
}

// nullableMAC maps the empty string to NULL, so "no MAC recorded" is one value
// in the column rather than two.
func nullableMAC(mac string) any {
	if mac == "" {
		return nil
	}
	return mac
}

// PutDevice inserts a device, or updates the MAC and status of one that exists.
// The trust class is fixed at registration: changing it would move the device's
// SSID, VLAN and any later service grants at once, so the service refuses it
// before this is reached.
func (p *Postgres) PutDevice(ctx context.Context, d tenant.Device) (tenant.Device, error) {
	var out tenant.Device
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// A device for a name the registry does not hold is a missing tenant,
		// which the caller can act on, rather than a foreign-key violation,
		// which it cannot. PutWiFiKey resolves the tenant the same way.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, d.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanDevice(tx.QueryRow(ctx,
			`INSERT INTO tenant_devices (tenant, name, trust_class, mac, status)
			      VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant, name) DO UPDATE
			         SET mac = EXCLUDED.mac, status = EXCLUDED.status, updated_at = now()
			   RETURNING `+deviceColumns,
			d.Tenant, d.Name, d.TrustClass, nullableMAC(d.MAC), string(d.Status)))
		return err
	})
	if err != nil {
		return tenant.Device{}, err
	}
	return out, nil
}

// GetDevice returns one device.
func (p *Postgres) GetDevice(ctx context.Context, tenantName, name string) (tenant.Device, error) {
	d, err := scanDevice(p.pool.QueryRow(ctx,
		`SELECT `+deviceColumns+` FROM tenant_devices WHERE tenant = $1 AND name = $2`, tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Device{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.Device{}, err
	}
	return d, nil
}

// ListDevices returns a tenant's devices, oldest first.
func (p *Postgres) ListDevices(ctx context.Context, tenantName string) ([]tenant.Device, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+deviceColumns+` FROM tenant_devices WHERE tenant = $1 ORDER BY created_at, name`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDevice removes the row. A device that is not there is not an error, so
// a repeated delete converges.
func (p *Postgres) DeleteDevice(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM tenant_devices WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}
