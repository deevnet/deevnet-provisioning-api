---
title: "Tenant Lifecycle"
weight: 3
---

# Tenant lifecycle

**A tenant is admitted by the operator, then creates itself.** Everything after admission is the
tenant's own call, made with its own token
([ADR-0015](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0015-tenant-onboarding-through-api/)).

## Admission

**`POST /v1/admissions` reserves a name and issues a single-use enrollment token.** Only the
operator may call it, and the operator hands the token to the tenant over a channel trusted with
a password.

At a site with a tenant developer network, the answer also carries a Wi-Fi key
([ADR-0029](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-networking/0029-tenant-developer-network-keys/)). The tenant needs that
network to reach the API at all, so the key cannot come from the tenant's own apply.

- **An optional `mac` binds the key to one computer.**
- **Admitting the name again** issues a new key, and the previous one stops working.
- **When the tenant creates itself**, the key becomes its own Wi-Fi key named `admission`: listed,
  deletable, and revoked when the tenant is deleted.
- **`DELETE /v1/admissions/{name}`** revokes the key of an admission that was never used. The
  enrollment token itself just expires.
- **Admitting a registered name** answers `409`.

## Create

**`POST /v1/tenants` with only a name creates a tenant.** The caller is the operator, the holder
of an enrollment token for that name, or the tenant itself.

The API then does three things:

1. **Allocates an index.** For a name the registry does not hold, it picks an index that no
   registry row holds and no fabric zone or VNet carries: the requested index if it is free,
   otherwise the index the fabric already uses for a zone of this name, otherwise the lowest free
   one.
2. **Ensures each backend in order**, recording each step's outcome:
   - `dns`: the forward and reverse zones and the tenant's update key
   - `resolver`: the site's resolver forwards both zones to the tenant DNS server
   - `state`: the state-store user and its prefix policy
   - `network`: the tenant's overlay zone, its VNet and subnet
   - `device-address`: the tenant's device address reservations, when it holds any
   - `log-store` and `dashboards`: the tenant's log tokens and dashboard login, at a site that
     has those stores
3. **Marks the tenant `ready`.**

Every step is an ensure. Objects that already exist are adopted and corrected, and a second run
changes nothing.

## Restore

**A restore is a create that sends back what the tenant's state holds.** That is the index and
all three secrets: the DNS update key, the state-store secret and the tenant's API token.

The `outcome` field says what happened:

| Status | `outcome` | When |
|---|---|---|
| `201` | `created` | new name, no index requested |
| `201` | `restored` | new name to the registry, requested index kept |
| `201` | `reissued` | new name to the registry, requested index held by another tenant, so a new one was issued |
| `200` | `resumed` | name registered but not `ready`: a previous create failed part way |
| `200` | `reconciled` | name registered and `ready`, and the request carried all three secrets, which replace the stored ones |

A registered, `ready` tenant created again with no secrets answers `409`.

## Resume

**A create that fails at a backend step answers `502` with the tenant in the body.** The tenant
is in status `provisioning`, the body carries its secrets, and calling create again resumes it
from the step that failed.

The `steps` array names each step and whether it succeeded. A step's error text is never
returned, because it can name backend hosts; it is in the service's log.

## What a tenant is issued

**The create response carries everything the tenant needs, and its secrets appear nowhere else.**

- **`dns`:** the tenant's zones, and the key that may update them.
- **`state`:** the state store's endpoint, bucket and prefix, and the tenant's credential.
- **`log`:** the tenant's access to the log store
  ([ADR-0027](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/platform-services/0027-tenant-log-store/)). `account_id` is its partition family:
  project 0 is what its own workloads ship, 1 what the substrate publishes about it, and 2 its
  devices' logs arriving over MQTT. A reader selects between them with the header `select_header`
  names, for example `X-Deevnet-Partition: 2-1`; without it a read returns project 0.
- **`dashboard`:** the tenant's dashboard login
  ([ADR-0024](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/platform-services/0024-dashboards/)): its own organization, where the login is an
  Editor and a member of nothing else.
- **`api_token`:** the tenant's own token.

The dashboard organization holds three data sources the tenant cannot change, each carrying its
log read token. Their UIDs are the same in every tenant's organization, so a dashboard that names
them moves between sites unchanged: `deevnet-logs-workloads` (project 0),
`deevnet-logs-platform` (1) and `deevnet-logs-devices` (2, the default).

## Reconcile

**`POST /v1/tenants/{name}/reconcile` re-ensures every backend with the secrets the registry
holds.** It is the operator's repair after a backend is rebuilt, and it puts device address
reservations back as well.

The answer carries no secrets, with one exception: the log tokens and the dashboard password are
returned, which is how a tenant created before those stores existed is handed them.

## Delete

**`DELETE /v1/tenants/{name}` removes everything the API built for the tenant, then its registry
row.** The operator or the tenant itself may call it.

| Status | When |
|---|---|
| `204` | the broker accounts, address reservations, resolver forwards, zones, update key, state-store user and dashboard login are removed. State objects stay in the bucket |
| `409` | the tenant still has workloads, or the fabric still carries a zone of this name. The tenant destroys its own resources first |
| `404` | not registered |
| `502` | a backend step failed. The tenant is left `deleting`, and a second delete resumes it |

The dashboard server cannot delete an organization
([grafana/grafana#127386](https://github.com/grafana/grafana/issues/127386)), so the emptied one is
renamed `deleted-<tenant>-<id>`, which frees the name for a tenant created again.
