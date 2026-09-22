-- A tenant's log store credentials (ADR-0027, CHG-0020).
--
-- Two columns on the tenant rather than a table of its own: a tenant has
-- exactly one pair, with nothing to name and nothing to list, which is the
-- same shape as its TSIG and state secrets and not the shape of its broker
-- accounts.
--
-- Sealed by Transit like those (ADR-0016 §3), but what an unreadable one costs
-- differs, and that difference is why ensure() re-mints rather than asking:
-- the log store is TOLD what the token is, so the API can issue a fresh pair
-- and write it. A TSIG key cannot be replaced that cheaply, because the
-- tenant's own copy is the authority.
--
-- DEFAULT '' so every tenant that already exists gets empty columns rather
-- than a failed migration; the next reconcile mints and writes the real pair.
ALTER TABLE tenants
    ADD COLUMN log_ingest_token text NOT NULL DEFAULT '',
    ADD COLUMN log_read_token   text NOT NULL DEFAULT '';
