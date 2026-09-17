# Deevnet API v1: tenants

The tenant slice of ADR-0015 (*Tenants Are Built Through the Deevnet API*), with credentials and
TLS from OpenBao (ADR-0016). Tenant routes answer `501` until the API is configured with a site
(`DEEVNET_SITE` and the rest, see the README), and `503` until its database schema is migrated.

## Who can call what

Every `/v1` request carries `Authorization: Bearer <token>`. The token is one of three things.

| Token | What it is | Can |
|---|---|---|
| **Operator** | `DEEVNET_API_TOKEN` | everything |
| **Tenant** | `dvt1.<tenant>.<nonce>.<mac>`, returned by create | read and delete its own tenant, restore itself, and its own future resources. Asking for another tenant answers `404`; operator-only routes answer `403`. |
| **Enrollment** | single-use, from `POST /v1/admissions` | create the tenant it was issued for, once. Nothing else. |

**How a tenant token is checked.** It carries a MAC keyed by `token_hmac_key`, which lives in
OpenBao, not in the registry.
- **Registered tenant:** the token is also checked against the hash the registry holds, so a
  replaced token is revoked.
- **Registry lost:** a genuine token still identifies its tenant, and may create (restore) that
  tenant and nothing else.

## Admit a tenant

`POST /v1/admissions`, operator only.

```json
{ "name": "tdemo" }
```

`201`:

```json
{ "name": "tdemo", "enrollment_token": "s.…", "expires_at": "2026-09-20T16:58:53Z" }
```

The token is OpenBao response wrapping: single-use, and valid for `DEEVNET_ENROLLMENT_TTL`
(default 72h). Deliver it to the tenant repository age-encrypted (ADR-0012 §9).
- **Presenting it for another name spends it** and answers `401`.
- **Admitting a registered name** answers `409`.
- **Without OpenBao configured**, admissions answer `501`, and only the operator creates tenants.

## Create, restore or resume a tenant

`POST /v1/tenants`, by any of:
- the operator
- the holder of an enrollment token for `name`, which spends it
- the tenant itself, with its own token: a resume, or a restore after the registry was lost

```json
{ "name": "tdemo" }
```

A **restore** sends back what the tenant's state holds: the index and all three secrets.

```json
{
  "name": "tdemo",
  "index": 2,
  "tsig_secret": "<base64, at least 16 bytes>",
  "state_secret": "<8-40 characters>",
  "api_token": "<at least 32 characters>"
}
```

| Field | Rules |
|---|---|
| `name` | `^[a-z][a-z0-9]{0,7}$`: the PVE SDN zone ID, a DNS label, a state-store user |
| `api_token` | on a restore, must be a token the API issued for `name` |
| `index` | optional, 1-62. 63 is reserved for drills and never allocated |
| secrets | all three or none |

### What the API does

1. **Allocate.** For a name the registry doesn't hold, the API picks an index that no registry row
   holds and no fabric zone or VNet carries:
   - the requested index, if it is free
   - otherwise the index the fabric already uses for a zone of this name
   - otherwise the lowest free index

   A tenant's own zone on the fabric doesn't count against it.
2. **Ensure** each backend in order, recording each step's outcome:
   - `dns`: forward and reverse zone, apex SOA and NS, TSIG key, update key and networks. A reverse
     zone bound to another tenant's key has its records cleared first.
   - `resolver`: the core router forwards both zones to the tenant DNS server
   - `state`: the state-store user and its prefix policy
3. **Mark the tenant `ready`.**

Every step is an ensure. Objects that already exist are adopted and corrected, and a second run
changes nothing.

### Status and `outcome`

| Status | `outcome` | When |
|---|---|---|
| `201` | `created` | new name, no index requested |
| `201` | `restored` | new name to the registry, requested index kept |
| `201` | `reissued` | new name to the registry, requested index held by another tenant, so a new one was issued |
| `200` | `resumed` | name registered but not `ready`; a previous create failed part way. Without secrets, a new API token is issued |
| `200` | `reconciled` | name registered and `ready`, and the request carried all three secrets. They replace the stored ones, and the registry's index is kept |
| `409` | | name registered and `ready`, no secrets supplied |
| `409` | | no free index |
| `400` | | invalid request; the body says why |
| `502` | | a backend step failed. The body is `{"error": "backend step \"state\" failed", "tenant": {...}}`, with the tenant in status `provisioning`. Calling create again resumes it |

### Response

Secrets appear in create responses only (`201`, `200`, and `502` with a tenant), because that is how
they reach the tenant's state. `api_token` is present when this call generated or received one.

```json
{
  "name": "tdemo",
  "index": 2,
  "status": "ready",
  "outcome": "created",
  "created_at": "2026-09-17T13:34:40Z",
  "updated_at": "2026-09-17T13:34:40Z",
  "network": { "vrf_vni": 10002, "vnet_vni_base": 20020, "subnet": "10.20.130.0/24", "gateway": "10.20.130.1" },
  "fabric": { "controller_id": "evpn1", "node": "dv02hyp002p02" },
  "dns": {
    "zone": "tdemo.mobile.deevnet.net",
    "reverse_zone": "130.20.10.in-addr.arpa",
    "update_server": "tdns.mobile.deevnet.net",
    "tsig_key_name": "tdemo",
    "tsig_algorithm": "hmac-sha256",
    "tsig_secret": "…"
  },
  "state": {
    "endpoint": "http://tfstate.mobile.deevnet.net:9000",
    "bucket": "tf-state",
    "key_prefix": "tenants/tdemo/",
    "access_key": "tdemo",
    "secret_key": "…"
  },
  "api_token": "…",
  "steps": [
    { "name": "dns", "ok": true, "updated_at": "…" },
    { "name": "resolver", "ok": true, "updated_at": "…" },
    { "name": "state", "ok": true, "updated_at": "…" }
  ]
}
```

Step error text is never returned: it can name backend hosts. It is in the log and in the
`tenant_steps` table.

## Read

- `GET /v1/tenants/{name}`: the tenant, without secrets. `404` if not registered. Operator, or the
  tenant itself.
- `GET /v1/tenants`: `{"tenants": [...]}` by index, without secrets. Operator only.

## Reconcile

`POST /v1/tenants/{name}/reconcile`, operator only, re-ensures every backend with the secrets the registry holds.
It is the repair after a backend is rebuilt. It returns the tenant with `outcome: reconciled` and no
secrets, or `502` as create does.

## Delete

`DELETE /v1/tenants/{name}`: operator, or the tenant itself.

| Status | When |
|---|---|
| `204` | the resolver forwards, zones, TSIG key, state user and policy are removed, then the registry row. State objects stay in the bucket |
| `409` | the fabric still carries a zone of this name. The tenant destroys its own resources first |
| `404` | not registered |
| `502` | a backend step failed. The tenant is left `deleting`, and a second delete resumes it |

## Egress list

`GET /v1/fabric/egress`, operator only, returns `{"vrfs": [{"tenant": "eds", "vrf": "vrf_eds"}]}` for every
`ready` tenant. It is what the exit node's agent will read (ADR-0015 §7).

## At rest and in transit

- **At rest.** With OpenBao configured, the TSIG and state-store secrets are stored as Transit
  ciphertext (`vault:v1:…`). A row written before that reads as it is, and is sealed the next time
  it is written.
- **In transit.** The API serves TLS when `DEEVNET_API_TLS_CERT` and `DEEVNET_API_TLS_KEY` are set,
  with a certificate issued by the site CA (OpenBao PKI).
