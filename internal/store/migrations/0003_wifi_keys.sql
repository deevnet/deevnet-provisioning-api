-- Tenant Wi-Fi keys (ADR-0012 §3, CHG-0013).
--
-- One PPSK key per tenant per trust class. There is no derived numbering here:
-- a key's identity is (tenant, name), and the name it carries inside the
-- controller's profile is "<tenant>-<name>", unique because tenant names are.
--
-- trust_class has no CHECK. The classes a site serves are configuration, not a
-- property of the schema, and a constraint here would need a migration just to
-- start serving iot_vendor.
CREATE TABLE tenant_wifi_keys (
    tenant      text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name        text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    trust_class text NOT NULL,
    -- Sealed by Transit like the other tenant secrets (ADR-0016 §3). The
    -- tenant's own Terraform state holds the authoritative copy (ADR-0012 §4),
    -- so a value that will not open costs a resupply, never a device visit.
    psk         text NOT NULL,
    status      text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
