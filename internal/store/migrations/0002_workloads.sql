-- ADR-0015 §12 and §13: the tenant's workloads, and the names it publishes
-- beside its workloads' own names.

CREATE TABLE tenant_workloads (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    -- A DNS label under the tenant's zone.
    name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    -- The tenant's own numbering: the VMID, MAC and address all derive from it,
    -- so it has to be unique within the tenant and stable for the workload's
    -- life. A freed ordinal is reused, which keeps addressing dense.
    ordinal    integer NOT NULL CHECK (ordinal >= 0),
    vmid       integer NOT NULL,
    mac        text NOT NULL,
    address    text NOT NULL,
    cores      integer NOT NULL CHECK (cores > 0),
    memory_mb  integer NOT NULL CHECK (memory_mb > 0),
    disk_gb    integer NOT NULL DEFAULT 0 CHECK (disk_gb >= 0),
    ssh_keys   text[] NOT NULL DEFAULT '{}',
    status     text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name),
    UNIQUE (tenant, ordinal)
);

CREATE TABLE tenant_records (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    address    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
