-- Tenant MQTT broker accounts (ADR-0012 §3, CHG-0016).
--
-- The registry's own record of what it asked the broker to hold. The broker
-- reads its accounts from a separate database on the messaging VM, which this
-- API never connects to - it sends them through the account writer instead,
-- because that database is not reachable from the network.
--
-- device is nullable: an account belongs either to one of the tenant's devices
-- or to a tenant workload, and a workload has none (ADR-0012 §3). No foreign
-- key to tenant_devices on purpose - the device is recorded as the tenant named
-- it, and a device removed from the registry should not silently take its
-- broker account with it. The API refuses the pairing at the door instead,
-- where it can say why.
--
-- password_hash is a bcrypt hash and is NOT sealed, unlike the Wi-Fi key in
-- 0003. That difference is deliberate. The controller needs a Wi-Fi key in
-- plaintext, so the API keeps a usable copy and seals it; the broker needs only
-- the hash, so the plaintext never reaches this database at all. Sealing the
-- hash would mean a Transit failure could leave an account unrestorable, and
-- the tenant's only recovery would be a new password and a visit to every
-- device holding the old one - which ADR-0012 §5 exists to prevent.
--
-- The hash is written BEFORE the writer is called, so a retry after an
-- ambiguous failure sends the same one and converges instead of rotating a
-- credential that devices are already flashed with.
CREATE TABLE tenant_broker_accounts (
    tenant        text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name          text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    device        text,
    password_hash text NOT NULL,
    -- Stored as the API sent them: already prefixed with the tenant's name
    -- (ADR-0012 §10). Kept so a restore re-sends exactly what was issued.
    publish_acl   jsonb NOT NULL,
    subscribe_acl jsonb NOT NULL,
    status        text NOT NULL CHECK (status IN ('provisioning', 'ready', 'deleting')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
