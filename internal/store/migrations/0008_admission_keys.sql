-- Tenant developer network keys (ADR-0029, CHG-0029).
--
-- A key may be bound to one client's MAC: the controller then admits it from
-- that MAC only. Empty binds nothing, which is every key issued before this.
ALTER TABLE tenant_wifi_keys ADD COLUMN mac text NOT NULL DEFAULT '';

-- The key an admission issues with its enrollment token, so a tenant developer
-- can join the tenant developer network before the tenant exists. It has no
-- tenant row to belong to yet, which is why it is not in tenant_wifi_keys; when
-- the tenant creates itself the key moves there as "admission" and this row
-- goes. One per name: a second admission replaces the first, and its key.
CREATE TABLE admission_keys (
    tenant      text PRIMARY KEY CHECK (tenant ~ '^[a-z][a-z0-9]{0,7}$'),
    -- Sealed by Transit like every stored tenant secret (ADR-0016 §3).
    psk         text NOT NULL,
    mac         text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
