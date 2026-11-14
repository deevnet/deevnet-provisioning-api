-- Tenant buckets and their keys (ADR-0026 §3, CHG-0069).
--
-- A bucket is "<tenant>-<name>" in the bucket store. Its quota is allocated
-- here, under the allocation lock: the sum of quota_gb over every tenant's
-- buckets never passes the configured capacity, so quotas are never
-- overcommitted.
CREATE TABLE tenant_buckets (
    tenant                 text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name                   text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,30}[a-z0-9]$'),
    quota_gb               integer NOT NULL CHECK (quota_gb >= 1),
    versioning             boolean NOT NULL DEFAULT false,
    -- Lifecycle rules, in days; 0 is none.
    expire_days            integer NOT NULL DEFAULT 0 CHECK (expire_days >= 0),
    noncurrent_expire_days integer NOT NULL DEFAULT 0 CHECK (noncurrent_expire_days >= 0),
    public_read            boolean NOT NULL DEFAULT false,
    status                 text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);

-- One key to one bucket. The access key is the store user's name, so it is
-- unique across every tenant: two keys can never be one user.
--
-- secret_key is sealed by Transit like the Wi-Fi key in 0003 (ADR-0016 §3),
-- not hashed like a broker password in 0005: the store is told the secret
-- itself, so the API keeps a usable copy to make the user again after a store
-- rebuild. The tenant's own state holds the authoritative one.
CREATE TABLE tenant_bucket_keys (
    tenant     text NOT NULL,
    bucket     text NOT NULL,
    name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    access     text NOT NULL CHECK (access IN ('read', 'write')),
    access_key text NOT NULL UNIQUE CHECK (access_key ~ '^[A-Z0-9]{20}$'),
    secret_key text NOT NULL,
    status     text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, bucket, name),
    FOREIGN KEY (tenant, bucket) REFERENCES tenant_buckets (tenant, name) ON DELETE CASCADE
);
