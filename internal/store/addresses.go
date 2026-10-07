package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Fixed device addresses (ADR-0035).
//
// Unlike Wi-Fi keys and devices these are allocated, and from a range every
// tenant shares, so a new one is picked under the same lock as a tenant index
// and a workload ordinal.

// The MAC is the device's, read through the join rather than stored twice.
const addressSelect = `
	SELECT a.tenant, a.device, a.trust_class, a.address, coalesce(d.mac, ''), a.status, a.created_at, a.updated_at
	  FROM tenant_device_addresses a
	  JOIN tenant_devices d ON d.tenant = a.tenant AND d.name = a.device`

func scanAddress(row pgx.Row) (tenant.DeviceAddress, error) {
	var a tenant.DeviceAddress
	var status string
	err := row.Scan(&a.Tenant, &a.Device, &a.TrustClass, &a.Address, &a.MAC, &status, &a.CreatedAt, &a.UpdatedAt)
	a.Status = tenant.Status(status)
	return a, err
}

func (p *Postgres) queryAddresses(ctx context.Context, q pgx.Tx, where string, args ...any) ([]tenant.DeviceAddress, error) {
	var (
		rows pgx.Rows
		err  error
	)
	sql := addressSelect + ` WHERE ` + where + ` ORDER BY a.created_at, a.tenant, a.device`
	if q != nil {
		rows, err = q.Query(ctx, sql, args...)
	} else {
		rows, err = p.pool.Query(ctx, sql, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.DeviceAddress
	for rows.Next() {
		a, err := scanAddress(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateDeviceAddress gives a device an address, or re-applies the one it
// holds. A new one is whatever pick returns, chosen while the allocation lock
// is held and with every address in the trust class in view.
func (p *Postgres) CreateDeviceAddress(ctx context.Context, a tenant.DeviceAddress, pick func([]tenant.DeviceAddress) (string, error)) (tenant.DeviceAddress, error) {
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, allocationLock); err != nil {
			return err
		}
		// The address is the device's for as long as it holds one; only the
		// status is taken.
		tag, err := tx.Exec(ctx,
			`UPDATE tenant_device_addresses SET status = $3, updated_at = now() WHERE tenant = $1 AND device = $2`,
			a.Tenant, a.Device, string(a.Status))
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			return nil
		}
		held, err := p.queryAddresses(ctx, tx, `a.trust_class = $1`, a.TrustClass)
		if err != nil {
			return err
		}
		address, err := pick(held)
		if err != nil {
			return err
		}
		// A device the registry does not hold is a foreign-key violation here.
		// The service has just read it, so that is a race with its deletion,
		// and "not found" is the truth.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenant_devices WHERE tenant = $1 AND name = $2)`, a.Tenant, a.Device).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO tenant_device_addresses (tenant, device, trust_class, address, status) VALUES ($1, $2, $3, $4, $5)`,
			a.Tenant, a.Device, a.TrustClass, address, string(a.Status))
		return err
	})
	if err != nil {
		return tenant.DeviceAddress{}, err
	}
	return p.GetDeviceAddress(ctx, a.Tenant, a.Device)
}

// GetDeviceAddress returns the address one device holds.
func (p *Postgres) GetDeviceAddress(ctx context.Context, tenantName, device string) (tenant.DeviceAddress, error) {
	a, err := scanAddress(p.pool.QueryRow(ctx, addressSelect+` WHERE a.tenant = $1 AND a.device = $2`, tenantName, device))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.DeviceAddress{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.DeviceAddress{}, err
	}
	return a, nil
}

// ListDeviceAddresses returns a tenant's addresses, oldest first.
func (p *Postgres) ListDeviceAddresses(ctx context.Context, tenantName string) ([]tenant.DeviceAddress, error) {
	return p.queryAddresses(ctx, nil, `a.tenant = $1`, tenantName)
}

// ListClassAddresses returns every tenant's addresses in one trust class.
func (p *Postgres) ListClassAddresses(ctx context.Context, trustClass string) ([]tenant.DeviceAddress, error) {
	return p.queryAddresses(ctx, nil, `a.trust_class = $1`, trustClass)
}

func (p *Postgres) SetDeviceAddressStatus(ctx context.Context, tenantName, device string, status tenant.Status) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE tenant_device_addresses SET status = $3, updated_at = now() WHERE tenant = $1 AND device = $2`,
		tenantName, device, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// DeleteDeviceAddress removes the row. One that is not there is not an error,
// so a repeated delete converges.
func (p *Postgres) DeleteDeviceAddress(ctx context.Context, tenantName, device string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM tenant_device_addresses WHERE tenant = $1 AND device = $2`, tenantName, device)
	return err
}
