-- API tokens of deleted tenants (CHG-0065).
--
-- A tenant token verifies by its MAC without the registry, so that a tenant
-- can restore itself after the registry is lost (ADR-0015 §5). While the
-- tenant is registered, the row's api_token_hash is what revokes every other
-- token issued for its name. A delete takes that row away, and without this
-- table the deleted tenant's token would then look exactly like a tenant
-- restoring after a registry loss, and could create its name again.
--
-- The tenant's delete writes its hash here in the same transaction that
-- removes the row, so there is never a moment with neither. A token whose hash
-- is here is refused whether or not its name is registered again later; a
-- tenant admitted again under the name is issued a new token.
--
-- No foreign key: a row exists precisely because its tenant does not. Nothing
-- is sealed: like api_token_hash, this is a SHA-256 of the token, not the
-- token.
--
-- If the registry itself is lost, this table goes with it and a deleted
-- tenant's token could restore its name. That is the exposure of any lost
-- registry, and is accepted (ADR-0033).
CREATE TABLE revoked_tenant_tokens (
    token_hash bytea PRIMARY KEY,
    tenant     text NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);
