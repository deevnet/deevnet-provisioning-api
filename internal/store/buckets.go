package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenant buckets and their keys (ADR-0026 §3, CHG-0069).
//
// A bucket's quota is admitted under the allocation lock, so two creates
// cannot both take the last of the capacity. A key's secret is sealed, as a
// Wi-Fi key's PSK is.

const bucketColumns = `tenant, name, quota_gb, versioning, expire_days, noncurrent_expire_days,
	public_read, status, created_at, updated_at`

func scanBucket(row pgx.Row) (tenant.Bucket, error) {
	var b tenant.Bucket
	var status string
	err := row.Scan(&b.Tenant, &b.Name, &b.QuotaGB, &b.Versioning, &b.ExpireDays, &b.NoncurrentExpireDays,
		&b.PublicRead, &status, &b.CreatedAt, &b.UpdatedAt)
	b.Status = tenant.Status(status)
	return b, err
}

// PutBucket inserts a bucket or updates one, refusing with a
// *tenant.CapacityError when a new bucket, or a larger quota, would take the
// sum of every tenant's quotas past capacityGB. A smaller or unchanged quota
// is never refused, even where capacity was since lowered beneath the sum.
func (p *Postgres) PutBucket(ctx context.Context, b tenant.Bucket, capacityGB int) (tenant.Bucket, error) {
	var out tenant.Bucket
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, allocationLock); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenants WHERE name = $1)`, b.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var others, old int
		if err := tx.QueryRow(ctx,
			`SELECT coalesce(sum(quota_gb) FILTER (WHERE NOT (tenant = $1 AND name = $2)), 0),
			        coalesce(sum(quota_gb) FILTER (WHERE tenant = $1 AND name = $2), 0)
			   FROM tenant_buckets`, b.Tenant, b.Name).Scan(&others, &old); err != nil {
			return err
		}
		if b.QuotaGB > old && others+b.QuotaGB > capacityGB {
			return &tenant.CapacityError{RequestedGB: b.QuotaGB, FreeGB: max(capacityGB-others, 0), CapacityGB: capacityGB}
		}
		var err error
		out, err = scanBucket(tx.QueryRow(ctx,
			`INSERT INTO tenant_buckets
			        (tenant, name, quota_gb, versioning, expire_days, noncurrent_expire_days, public_read, status)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (tenant, name) DO UPDATE
			        SET quota_gb = EXCLUDED.quota_gb,
			            versioning = EXCLUDED.versioning,
			            expire_days = EXCLUDED.expire_days,
			            noncurrent_expire_days = EXCLUDED.noncurrent_expire_days,
			            public_read = EXCLUDED.public_read,
			            status = EXCLUDED.status,
			            updated_at = now()
			 RETURNING `+bucketColumns,
			b.Tenant, b.Name, b.QuotaGB, b.Versioning, b.ExpireDays, b.NoncurrentExpireDays, b.PublicRead, string(b.Status)))
		return err
	})
	if err != nil {
		return tenant.Bucket{}, err
	}
	return out, nil
}

func (p *Postgres) GetBucket(ctx context.Context, tenantName, name string) (tenant.Bucket, error) {
	b, err := scanBucket(p.pool.QueryRow(ctx,
		`SELECT `+bucketColumns+` FROM tenant_buckets WHERE tenant = $1 AND name = $2`, tenantName, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Bucket{}, tenant.ErrNotFound
	}
	return b, err
}

func (p *Postgres) ListBuckets(ctx context.Context, tenantName string) ([]tenant.Bucket, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+bucketColumns+` FROM tenant_buckets WHERE tenant = $1 ORDER BY created_at, name`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenant.Bucket
	for rows.Next() {
		b, err := scanBucket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *Postgres) SetBucketStatus(ctx context.Context, tenantName, name string, status tenant.Status) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE tenant_buckets SET status = $3, updated_at = now() WHERE tenant = $1 AND name = $2`,
		tenantName, name, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// DeleteBucket removes the row, and its keys' rows with it. A bucket that is
// not there is not an error.
func (p *Postgres) DeleteBucket(ctx context.Context, tenantName, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM tenant_buckets WHERE tenant = $1 AND name = $2`, tenantName, name)
	return err
}

const bucketKeyColumns = `tenant, bucket, name, access, access_key, secret_key, status, created_at, updated_at`

func scanBucketKey(row pgx.Row) (tenant.BucketKey, error) {
	var k tenant.BucketKey
	var status string
	err := row.Scan(&k.Tenant, &k.Bucket, &k.Name, &k.Access, &k.AccessKey, &k.SecretKey, &status, &k.CreatedAt, &k.UpdatedAt)
	k.Status = tenant.Status(status)
	return k, err
}

// PutBucketKey inserts a key or updates one. The row goes down before the
// store is told, so a retry finds the same access key and secret.
func (p *Postgres) PutBucketKey(ctx context.Context, k tenant.BucketKey) (tenant.BucketKey, error) {
	secret, err := p.sealOne(ctx, k.SecretKey)
	if err != nil {
		return tenant.BucketKey{}, err
	}
	var out tenant.BucketKey
	err = pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenant_buckets WHERE tenant = $1 AND name = $2)`, k.Tenant, k.Bucket).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return tenant.ErrNotFound
		}
		var err error
		out, err = scanBucketKey(tx.QueryRow(ctx,
			`INSERT INTO tenant_bucket_keys (tenant, bucket, name, access, access_key, secret_key, status)
			      VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (tenant, bucket, name) DO UPDATE
			         SET access = EXCLUDED.access, access_key = EXCLUDED.access_key,
			             secret_key = EXCLUDED.secret_key, status = EXCLUDED.status, updated_at = now()
			   RETURNING `+bucketKeyColumns,
			k.Tenant, k.Bucket, k.Name, k.Access, k.AccessKey, secret, string(k.Status)))
		return err
	})
	if err != nil {
		return tenant.BucketKey{}, err
	}
	// Hand back what the caller gave us, not what we sealed.
	out.SecretKey = k.SecretKey
	return out, nil
}

func (p *Postgres) GetBucketKey(ctx context.Context, tenantName, bucket, name string) (tenant.BucketKey, error) {
	k, err := scanBucketKey(p.pool.QueryRow(ctx,
		`SELECT `+bucketKeyColumns+` FROM tenant_bucket_keys WHERE tenant = $1 AND bucket = $2 AND name = $3`,
		tenantName, bucket, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.BucketKey{}, tenant.ErrNotFound
	}
	if err != nil {
		return tenant.BucketKey{}, err
	}
	return p.openBucketKey(ctx, k)
}

func (p *Postgres) ListBucketKeys(ctx context.Context, tenantName, bucket string) ([]tenant.BucketKey, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+bucketKeyColumns+` FROM tenant_bucket_keys WHERE tenant = $1 AND bucket = $2 ORDER BY created_at, name`,
		tenantName, bucket)
	if err != nil {
		return nil, err
	}
	var all []tenant.BucketKey
	for rows.Next() {
		k, err := scanBucketKey(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Opened after the rows are closed: each open is a request to OpenBao,
	// and the connection is not held across them.
	for i := range all {
		if all[i], err = p.openBucketKey(ctx, all[i]); err != nil {
			return nil, err
		}
	}
	return all, nil
}

func (p *Postgres) SetBucketKeyStatus(ctx context.Context, tenantName, bucket, name string, status tenant.Status) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE tenant_bucket_keys SET status = $4, updated_at = now() WHERE tenant = $1 AND bucket = $2 AND name = $3`,
		tenantName, bucket, name, string(status))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tenant.ErrNotFound
	}
	return nil
}

// DeleteBucketKey removes the row. A key that is not there is not an error.
func (p *Postgres) DeleteBucketKey(ctx context.Context, tenantName, bucket, name string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM tenant_bucket_keys WHERE tenant = $1 AND bucket = $2 AND name = $3`, tenantName, bucket, name)
	return err
}

func (p *Postgres) openBucketKey(ctx context.Context, k tenant.BucketKey) (tenant.BucketKey, error) {
	if p.sealer == nil {
		return k, nil
	}
	var err error
	if k.SecretKey, k.Unreadable, err = p.openOne(ctx, k.SecretKey, "bucket-key"); err != nil {
		return tenant.BucketKey{}, err
	}
	return k, nil
}
