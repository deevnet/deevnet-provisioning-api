---
title: "Tenant Secrets"
weight: 5
---

# Tenant secrets

**A tenant keeps its runtime secrets in its own namespace of the site's OpenBao, and each workload
reads only the paths the tenant assigns to it.** The tenant writes through the API; the workload
reads from OpenBao directly, under its own AppRole
([ADR-0021](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0021-tenant-secrets/)).
The service is optional: a site that does not offer it answers `501` on these routes. The
[API Reference](/docs/reference/) has every field; this page is what the fields do not say.

## The namespace

**Each tenant has one namespace, `tenants/<name>`, with two mounts:** a KV version 2 engine at
`secrets` and an AppRole auth method at `approle`. The API makes it as a step of create and
reconcile, named `secrets`, and deletes it, with everything in it, first when the tenant is
deleted. A reconcile after the namespace was lost makes it again, empty.

## Writing a secret

**`PUT /v1/tenants/{name}/secrets/{path}` writes a value, and nothing ever reads it back through
the API.** The API's own OpenBao policy has no read on the tenant's values.

- **The path** is 1 to 4 segments of `[a-z0-9_-]{1,64}` joined by `/`, at most 128 characters.
  It is the rest of the URL, so `secrets/weather/api` and `secrets/weather%2Fapi` are the same.
- **The version** is the tenant's, not OpenBao's. A new value comes with a new version; the API
  records it and reports it back.
- **The value is a copy.** The tenant's repository holds the authoritative one. After OpenBao is
  rebuilt, a read of the secret is `404`, and the next apply writes it again.

## Readers

**`PUT /v1/tenants/{name}/secret-readers/{reader}` gives one workload read access to named
paths, and returns the credential it logs in with.**

| Field | What it is |
|---|---|
| `role_id` | the AppRole's role ID; not secret, and returned on every read |
| `secret_id` | the AppRole's secret ID; returned by this call only. The tenant keeps it in state and pushes it to the workload |
| `namespace`, `addr` | where the workload logs in: `tenants/<name>` on the site's OpenBao |

- **It is bound to the workload's address.** The secret ID and every token it gets are refused
  from any other address.
- **It is reusable and does not expire.** The workload logs in again each time its service starts.
  Tokens live an hour, renewable to a day.
- **Each call issues a new one.** The old AppRole is deleted first, so a secret ID issued before
  stops logging in.
- **Each path must be a secret the tenant has written.** Anything else is a `400`.

**Revoking a reader deletes its AppRole and its policy.** Deleting the AppRole alone would stop new
logins and leave a token already issued working until it expired; deleting the policy cuts that
token off at its next request. **Destroying a workload revokes its readers.**
