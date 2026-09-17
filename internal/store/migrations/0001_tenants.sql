-- ADR-0015: the API's database is the registry of tenants.

CREATE TABLE tenants (
    -- The PVE SDN zone ID, verbatim (ADR-0002 naming constraint).
    name           text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9]{0,7}$'),
    -- ADR-0002's single number. UNIQUE is what makes a collision impossible
    -- inside the registry; the allocator also checks the fabric.
    idx            integer NOT NULL UNIQUE CHECK (idx BETWEEN 1 AND 63),
    status         text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    -- Kept usable: the API re-ensures them after a backend is rebuilt. The
    -- authoritative copy is the tenant's state (ADR-0015 §4).
    tsig_secret    text NOT NULL,
    state_secret   text NOT NULL,
    -- SHA-256 of the tenant's API token; the token itself is never stored.
    api_token_hash bytea NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- The last outcome of each backend step, so a partial tenant is visible.
CREATE TABLE tenant_steps (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    step       text NOT NULL,
    ok         boolean NOT NULL,
    error      text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, step)
);

-- No foreign key: the record of what was done to a tenant outlives the tenant.
CREATE TABLE audit_log (
    id     bigserial PRIMARY KEY,
    at     timestamptz NOT NULL DEFAULT now(),
    actor  text NOT NULL,
    action text NOT NULL,
    tenant text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_tenant_at ON audit_log (tenant, at);
