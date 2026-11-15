-- Tenant alerting (ADR-0023 §5, CHG-0071).
--
-- notify_password is the tenant's ntfy login, sealed like the dashboard
-- password and lost the same way: ntfy is told what it is (as a hash, by the
-- log store's writer), so an unreadable one is re-minted rather than asked for.
-- DEFAULT '' so every tenant migrates; the next reconcile mints it.
ALTER TABLE tenants
    ADD COLUMN notify_password text NOT NULL DEFAULT '';

-- A tenant's alert rule groups. The rules are the tenant's own text, checked
-- by the API and again by the writer and vmalert before they run; they hold no
-- secret, so nothing here is sealed. jsonb keeps a group one row: the
-- provider replaces a group's rules as a whole.
CREATE TABLE tenant_alert_rule_groups (
    tenant     text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
    type       text NOT NULL CHECK (type IN ('metrics', 'logs')),
    interval   text NOT NULL,
    topic      text NOT NULL CHECK (topic ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    partition  text NOT NULL CHECK (partition IN ('workloads', 'platform', 'devices')),
    rules      jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
