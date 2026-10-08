---
title: "Authentication"
weight: 2
---

# Authentication

**Every `/v1` request carries `Authorization: Bearer <token>`.** A request without a token the
API recognizes answers `401` with `WWW-Authenticate: Bearer realm="deevnet-api"`. The three
service routes, `/healthz`, `/readyz` and `/version`, take no token.

## Tokens

**The token is one of four things, and it decides what the caller may do.**

| Token | What it is | May |
|---|---|---|
| **Operator** | the site's operator token | everything |
| **Tenant** | `dvt1.<tenant>.<nonce>.<mac>`, returned when the tenant is created | read and delete its own tenant, restore itself, and manage its own workloads, names, devices, keys and accounts |
| **Enrollment** | single-use, issued by an admission | create the one tenant it was issued for, once |
| **Egress agent** | the exit node's token | read `GET /v1/fabric/egress`, nothing else |

A tenant holds exactly one of these at a time: the enrollment token for its first apply, then its
own token for every later one.

## What a tenant sees

**A tenant asking for another tenant's name is told it does not exist.** The answer is `404`
rather than `403`, so a token cannot be used to discover which tenants a site has. An
operator-only route answers a tenant `403`.

## Tenant tokens

**A tenant token verifies without the registry.** It carries a MAC keyed by a key that lives in
the site's secret store, not in the API's database
([ADR-0015](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0015-tenant-onboarding-through-api/) §5).

- **Registered tenant:** the token is also checked against the hash the registry holds, so a
  replaced token is revoked.
- **Registry lost:** a genuine token still identifies its tenant, and may create (restore) that
  tenant and nothing else. That is what lets a tenant put itself back after the API's database
  is rebuilt.

The API stores a tenant's token only as a hash. The copy in the tenant's Terraform state is the
only readable one.

## Enrollment tokens

**An enrollment token is single-use and expires.** It is valid for the site's enrollment lifetime,
72 hours by default, and the first `POST /v1/tenants` that presents it spends it. Presenting it
for a name other than the one it was issued for also spends it, and answers `401`.

[Tenant Lifecycle](/docs/tenant-lifecycle/) covers how one is issued.

## Transport

**The API serves TLS with a certificate from the site's certificate authority.** A caller verifies
it against the Deevnet Root CA; the provider reads that file's path from `DEEVNET_API_CACERT`.
