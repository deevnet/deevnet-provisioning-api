---
title: "Conventions"
weight: 5
---

# Conventions

**Every route follows the same few rules.** They are what make a failed or repeated call safe.

## Ensures

**Every create is an ensure.** Calling it again for the same name converges on the same object:
the identity stays, an issued secret is kept, and only what the caller may change is taken. An
object that already exists on a backend is adopted and corrected.

This is what makes a retry safe, and it is why a tenant's Terraform can re-apply after any
failure.

## Partial objects

**A create that fails at a backend step answers `502` with the object in the body.** The object
is under a key named for its kind: `tenant`, `workload`, `address`, `wifi_key` or
`broker_account`. Any secret issued with it is included.

The caller records what it was given, and the same call resumes from the step that failed. The
error names the step only:

```json
{ "error": "backend step \"state\" failed", "tenant": { "name": "tdemo", "status": "provisioning" } }
```

## Secrets

**Secrets appear in create responses, and a read never returns one.** That is how they reach the
caller's state, which is their authoritative copy
([ADR-0015](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0015-tenant-onboarding-through-api/) §4).

- **Supplied secrets win over stored ones.** A restore sends the caller's copy back, and the
  backends are made to match it.
- **`secrets_stored`** on a tenant or a Wi-Fi key is `false` when the API holds a secret it can
  no longer read. The caller then supplies it again.
- **A reconcile returns the log tokens and the dashboard password**, and no other secret.

## Errors

**An error is `{"error": "..."}`, and the text is safe to show.** It never names a backend host
and never carries a secret; a failed step's detail goes to the service's log.

| Status | Means |
|---|---|
| `400` | invalid request; the text says why |
| `401` | no token, or one the API does not recognize |
| `403` | a tenant token on an operator-only route |
| `404` | no such object, or another tenant's |
| `409` | a conflict: a name already registered, nothing free to allocate, or something still in use |
| `501` | a route that is not implemented, or enrollment at a site that does not configure it |
| `502` | a backend step failed; the same call resumes it |
| `503` | the database schema is not migrated yet |

## Requests

**Request bodies are JSON, and unknown fields are refused.** A misspelled field answers `400`
rather than being ignored. A body is capped at 64 KB, and an admission's at 4 KB.

## Optional capabilities

**A site may serve only part of the API.** Wi-Fi keys, fixed addresses, broker accounts, the log
store and dashboards each depend on a service the site may not run. Their routes then refuse with
a reason, and a tenant's answer simply omits what the site does not have. A site with no wireless
controller or no broker is a legitimate site.

## At rest and in transit

**Stored secrets are sealed, and the API serves TLS.**

- **At rest.** Secrets the API must be able to read back are encrypted by the site's secret store
  before they reach the database ([ADR-0016](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/substrate/0016-substrate-secrets-openbao/)). Tenant
  tokens and broker passwords are stored only as hashes.
- **In transit.** The API serves TLS with a certificate issued by the site's certificate
  authority.
