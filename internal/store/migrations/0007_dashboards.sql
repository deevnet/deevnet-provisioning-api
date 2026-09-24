-- A tenant's dashboard login and organisation (ADR-0024, CHG-0024).
--
-- The password is sealed like the log tokens and costs the same when lost: the
-- dashboard server is told what it is, so an unreadable one is re-minted and
-- written rather than asked for. The organisation id is not a secret; the
-- server chooses it, and it is kept so the tenant can be told it.
--
-- DEFAULT '' and 0 so every tenant that already exists migrates; the next
-- reconcile creates the organisation and fills both.
ALTER TABLE tenants
    ADD COLUMN dashboard_password text    NOT NULL DEFAULT '',
    ADD COLUMN dashboard_org      integer NOT NULL DEFAULT 0;
