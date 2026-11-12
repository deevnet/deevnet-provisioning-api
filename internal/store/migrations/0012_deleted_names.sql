-- Names of deleted tenants (CHG-0065).
--
-- 0011 revokes the token a deleted tenant's row held, by its hash. That
-- covers deletes from then on, but not a tenant deleted before it, whose hash
-- went with its row: such a token still verified by its MAC and, with no row
-- for its name, was taken for a tenant restoring after a lost registry.
--
-- A name here answers that for every token at once: a tenant token whose name
-- is not registered but is here is refused, whatever its hash. A deleted name
-- comes back only through admission, which issues a new token; once it is
-- registered again, the row's hash decides, as for any registered tenant.
-- Restoring after a lost registry is unaffected: this table is lost with it.
--
-- The audit log has recorded every delete since the first migration, so it
-- seeds the names deleted before this table existed.
CREATE TABLE deleted_tenant_names (
    tenant     text PRIMARY KEY,
    deleted_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO deleted_tenant_names (tenant, deleted_at)
SELECT tenant, max(at) FROM audit_log WHERE action = 'delete' GROUP BY tenant;
