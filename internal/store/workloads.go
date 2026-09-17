package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Workloads and published names (ADR-0015 §12, §13).

const (
	workloadInsert  = `tenant, name, ordinal, vmid, mac, address, cores, memory_mb, disk_gb, ssh_keys, status`
	workloadColumns = workloadInsert + `, created_at, updated_at`
)

func scanWorkload(row pgx.Row) (tenant.Workload, error) {
	var w tenant.Workload
	var status string
	err := row.Scan(&w.Tenant, &w.Name, &w.Ordinal, &w.VMID, &w.MAC, &w.Address,
		&w.Cores, &w.MemoryMB, &w.DiskGB, &w.SSHKeys, &status, &w.CreatedAt, &w.UpdatedAt)
	w.Status = tenant.Status(status)
	return w, err
}

// CreateWorkload inserts a workload, or updates the sizing of one that exists.
// A new workload's ordinal is the lowest free one for that tenant, allocated
// under the same lock as a tenant index, and its VMID, MAC and address derive
// from it.
func (p *Postgres) CreateWorkload(ctx context.Context, w tenant.Workload) (tenant.Workload, error) {
	var out tenant.Workload
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, allocationLock); err != nil {
			return err
		}

		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenant_workloads WHERE tenant = $1 AND name = $2)`, w.Tenant, w.Name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			// Identity is the workload's for life; only sizing is taken.
			var err error
			out, err = scanWorkload(tx.QueryRow(ctx,
				`UPDATE tenant_workloads
				    SET cores = $3, memory_mb = $4, disk_gb = $5, ssh_keys = $6, updated_at = now()
				  WHERE tenant = $1 AND name = $2
				  RETURNING `+workloadColumns,
				w.Tenant, w.Name, w.Cores, w.MemoryMB, w.DiskGB, keysOrEmpty(w.SSHKeys)))
			return err
		}

		var index int
		if err := tx.QueryRow(ctx, `SELECT idx FROM tenants WHERE name = $1`, w.Tenant).Scan(&index); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return tenant.ErrNotFound
			}
			return err
		}

		rows, err := tx.Query(ctx, `SELECT ordinal FROM tenant_workloads WHERE tenant = $1`, w.Tenant)
		if err != nil {
			return err
		}
		taken := map[int]bool{}
		var ordinal int
		if _, err := pgx.ForEachRow(rows, []any{&ordinal}, func() error {
			taken[ordinal] = true
			return nil
		}); err != nil {
			return err
		}
		next := -1
		for n := 0; n < tenant.MaxWorkloads; n++ {
			if !taken[n] {
				next = n
				break
			}
		}
		if next < 0 {
			return tenant.ErrWorkloadsExhausted
		}

		if w.SSHKeys == nil {
			w.SSHKeys = []string{}
		}
		w.Ordinal = next
		w.VMID = p.site.WorkloadVMID(index, next)
		w.MAC = p.site.MAC(w.VMID)
		w.Address = p.site.WorkloadAddress(index, next)
		out, err = scanWorkload(tx.QueryRow(ctx,
			`INSERT INTO tenant_workloads (`+workloadInsert+`)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			 RETURNING `+workloadColumns,
			w.Tenant, w.Name, w.Ordinal, w.VMID, w.MAC, w.Address, w.Cores, w.MemoryMB, w.DiskGB, w.SSHKeys, string(w.Status)))
		return err
	})
	return out, err
}

func keysOrEmpty(keys []string) []string {
	if keys == nil {
		return []string{}
	}
	return keys
}

func (p *Postgres) GetWorkload(ctx context.Context, tenantName, name string) (tenant.Workload, error) {
	w, err := scanWorkload(p.pool.QueryRow(ctx,
		`SELECT `+workloadColumns+` FROM tenant_workloads WHERE tenant = $1 AND name = $2`, tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Workload{}, tenant.ErrNotFound
	}
	return w, err
}

func (p *Postgres) ListWorkloads(ctx context.Context, tenantName string) ([]tenant.Workload, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+workloadColumns+` FROM tenant_workloads WHERE tenant = $1 ORDER BY ordinal`, tenantName)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.Workload, error) { return scanWorkload(row) })
}

func (p *Postgres) SetWorkloadStatus(ctx context.Context, tenantName, name string, status tenant.Status) error {
	return p.execOne(ctx,
		`UPDATE tenant_workloads SET status = $3, updated_at = now() WHERE tenant = $1 AND name = $2`,
		tenantName, name, string(status))
}

func (p *Postgres) DeleteWorkload(ctx context.Context, tenantName, name string) error {
	return p.execOne(ctx, `DELETE FROM tenant_workloads WHERE tenant = $1 AND name = $2`, tenantName, name)
}

func (p *Postgres) PutRecord(ctx context.Context, r tenant.ExtraRecord) error {
	_, err := p.pool.Exec(ctx,
		`INSERT INTO tenant_records (tenant, name, address) VALUES ($1, $2, $3)
		 ON CONFLICT (tenant, name) DO UPDATE SET address = EXCLUDED.address`,
		r.Tenant, r.Name, r.Address)
	return err
}

func (p *Postgres) ListRecords(ctx context.Context, tenantName string) ([]tenant.ExtraRecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT tenant, name, address, created_at FROM tenant_records WHERE tenant = $1 ORDER BY name`, tenantName)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.ExtraRecord, error) {
		var r tenant.ExtraRecord
		err := row.Scan(&r.Tenant, &r.Name, &r.Address, &r.CreatedAt)
		return r, err
	})
}

func (p *Postgres) DeleteRecord(ctx context.Context, tenantName, name string) error {
	return p.execOne(ctx, `DELETE FROM tenant_records WHERE tenant = $1 AND name = $2`, tenantName, name)
}
