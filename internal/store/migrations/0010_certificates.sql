-- Server certificates the API issued for tenants' own services (ADR-0037,
-- CHG-0047).
--
-- Everything here is public. A certificate is something a server hands to
-- anyone who connects, and the key it certifies was made by the tenant and
-- never came to the API: only a signing request did. So nothing is sealed,
-- and there is nothing here to protect beyond the row itself.
--
-- It is kept for one reason: so that asking again is an ensure. A tenant's
-- apply sends the same request every time, and the same certificate has to
-- come back while it has time left, or every apply would mint another and
-- every plan would show a change. key_fingerprint is how "the same request"
-- is told: it is the SHA-256 of the public key in the request, and a new key
-- is a new certificate.
--
-- One row per name, holding the certificate current for it. Reissuing
-- replaces the row. The one it replaces is not kept and is not revoked:
-- nothing on the site can revoke a certificate, and it stays valid until it
-- expires wherever its key still is. The audit log has each one's serial.
--
-- names is every DNS name in the certificate, fully qualified, its own first.
-- It is stored whole, not derived, because the zone is derived from the site
-- and a certificate is a statement about what was issued, not about what
-- would be issued now.
--
-- No status column, unlike the tables before it. Those rows are written
-- before a backend is told, so that a retry converges, and a row can be
-- caught between the two. This row is written after the signer has answered
-- and its answer has been checked, so a row that exists is always a
-- certificate.
CREATE TABLE tenant_certificates (
    tenant          text NOT NULL REFERENCES tenants (name) ON DELETE CASCADE,
    name            text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,19}$'),
    names           jsonb NOT NULL,
    key_fingerprint text NOT NULL,
    serial          text NOT NULL,
    not_before      timestamptz NOT NULL,
    not_after       timestamptz NOT NULL,
    certificate     text NOT NULL,
    chain           text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);
