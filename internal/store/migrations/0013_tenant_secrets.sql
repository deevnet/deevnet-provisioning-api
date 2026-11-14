-- Tenant runtime secrets (ADR-0021, CHG-0067).
--
-- Metadata only. A secret's value goes to the tenant's own OpenBao namespace
-- and nowhere else: the API's policy cannot even read it back. What is kept
-- here is what the provider needs to plan with - that a secret was declared,
-- at which path, and the tenant's own version of it - and which paths each
-- workload's reader was granted, so a workload's destroy can revoke them.
--
-- The path is the tenant's name for the secret inside its KV mount: one to
-- four segments of [a-z0-9_-]{1,64}, at most 128 characters. The service
-- refuses anything else before it reaches OpenBao; the CHECK says the same.
CREATE TABLE tenant_runtime_secrets (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    path       text NOT NULL CHECK (
                   path ~ '^[a-z0-9_-]{1,64}(/[a-z0-9_-]{1,64}){0,3}$' AND length(path) <= 128),
    -- The tenant's version, not OpenBao's: a new value comes with a new one.
    version    integer NOT NULL CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, path)
);

-- One workload's AppRole in the tenant's namespace, and the paths its policy
-- reads. The role ID and secret ID are not kept: the role ID is read from
-- OpenBao, and the secret ID is handed to the tenant once.
--
-- No foreign key to tenant_workloads, on purpose: a cascade there would drop
-- the row and leave the AppRole in OpenBao. The service revokes a workload's
-- readers, in OpenBao and here, before it removes the workload.
CREATE TABLE tenant_secret_readers (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name       text NOT NULL CHECK (name ~ '^[a-z0-9-]{1,32}$'),
    workload   text NOT NULL,
    paths      jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
