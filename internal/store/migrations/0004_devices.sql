-- The tenant device registry (ADR-0012 §3), ordered first by ADR-0020's
-- implementation notes: the contract's §2 and §5 need somewhere to record what
-- a device may consume, and this is it.
--
-- Like Wi-Fi keys and unlike workloads, nothing here is derived or allocated: a
-- device's identity is (tenant, name), the name being the tenant's own label.
--
-- trust_class has no CHECK, for the same reason as 0003: the classes a site
-- serves are configuration, not a property of the schema, and a constraint here
-- would need a migration just to start serving iot_vendor.
--
-- mac is nullable and carries no UNIQUE constraint, deliberately on both
-- counts. It is a label for the owner's own inventory and is never an
-- authorization input (ADR-0020 §2), so the substrate has nothing to enforce
-- with it. A cross-tenant UNIQUE would be worse than useless: it would make a
-- conflict disclose that another tenant holds that address, which is precisely
-- what the API's 404-rather-than-403 scoping exists to prevent.
--
-- No sealing. A device row holds no secret. When a per-device credential lands
-- (ADR-0020 §2 leaves the mechanism open) it arrives as its own column in its
-- own migration, sealed like the PSK in 0003.
CREATE TABLE tenant_devices (
    tenant      text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name        text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    trust_class text NOT NULL,
    mac         text,
    status      text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
