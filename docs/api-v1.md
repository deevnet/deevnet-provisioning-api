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
  "api_token": "<the tenant token the API issued>"
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
   - `network`: the EVPN zone, its VNet and the SNAT subnet, then an SDN apply. Applies are
     cluster-wide, so the API runs one at a time.
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
  "log": {
    "endpoint": "https://dv02obs001v01.mobile.deevnet.net:8427",
    "account_id": 2,
    "select_header": "X-Deevnet-Partition",
    "ingest_token": "…",
    "read_token": "…"
  },
  "api_token": "…",
  "steps": [
    { "name": "dns", "ok": true, "updated_at": "…" },
    { "name": "resolver", "ok": true, "updated_at": "…" },
    { "name": "state", "ok": true, "updated_at": "…" },
    { "name": "log-store", "ok": true, "updated_at": "…" }
  ]
}
```

Step error text is never returned: it can name backend hosts. It is in the log and in the
`tenant_steps` table.

`log` is the tenant's access to the log store (ADR-0027). `account_id` is its partition family:
project 0 is what its own workloads ship, 1 what the substrate publishes about it, and 2 its
devices' logs arriving over MQTT. A reader selects between them with the `select_header`, for
example `X-Deevnet-Partition: 2-1`; without it a read returns project 0. The two tokens appear
under the same rule as the other secrets, and **also on a reconcile**, which is how a tenant created
before the store existed is handed them. `endpoint` and `log-store` are absent at a site with no
store.

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

## Workloads

A workload is a VM in the tenant's network (ADR-0015 §12). The operator or the tenant may call these.

`POST /v1/tenants/{name}/workloads`

```json
{ "name": "web", "cores": 2, "memory_mb": 2048, "disk_gb": 40, "ssh_keys": ["ssh-ed25519 AAAA..."] }
```

- **The tenant chooses** the name, sizing and keys. `cores` and `memory_mb` default to 2 and 2048;
  `disk_gb` grows the template's disk and never shrinks it.
- **The API chooses** everything else, and it is stable for the workload's life:
  - **ordinal:** the lowest free one for that tenant, reused after a delete
  - **VMID:** `tenant VMID base + index * 40 + ordinal`
  - **MAC:** derived from the VMID (`standards/mac-naming`)
  - **address:** `.10 + ordinal` in the tenant's subnet
  - **node, template, storage:** the site's; the template is the newest by name prefix
- **It also publishes** `<name>.<tenant zone>` and the matching PTR.
- **Calling it again** for the same name re-applies: the identity stays, the sizing is taken.

`201` with the workload. `502` when the hypervisor or DNS step fails, with the workload in the body
so a retry resumes. `409` when the tenant has no free ordinal.

| Route | Does |
|---|---|
| `GET /v1/tenants/{name}/workloads` | the tenant's workloads, by ordinal |
| `GET /v1/tenants/{name}/workloads/{workload}` | one workload |
| `DELETE /v1/tenants/{name}/workloads/{workload}` | removes the VM and its published names |

**A tenant with workloads is not deleted:** `DELETE /v1/tenants/{name}` answers `409` until they are
gone.

## Published names

Names beside the workloads' own (ADR-0015 §13), such as eds's `palette` and `lightd`.

| Route | Does |
|---|---|
| `PUT /v1/tenants/{name}/records/{record}` with `{"address": "10.20.129.10"}` | publishes `<record>.<tenant zone>` and its PTR |
| `GET /v1/tenants/{name}/records` | the names the tenant added |
| `DELETE /v1/tenants/{name}/records/{record}` | removes one |

The address must be in the tenant's own subnet. The tenant's TSIG key still works for anything it
would rather publish itself (ADR-0004).

## Devices

A tenant's registry of its own edge devices (ADR-0012 §3). The entry **is** the device's identity:
an application-owned device takes no substrate host record, leases from its trust class's pool, and
is named in its owner's own zone (ADR-0011 open question 3).

`POST /v1/tenants/{name}/devices`

```json
{ "name": "stand-1", "trust_class": "iot", "mac": "aa:bb:cc:dd:ee:ff" }
```

- **The tenant chooses** the device's name, its trust class, and optionally records a MAC.
- **`mac` is optional, and the substrate enforces nothing with it.** It is a label for the owner's
  own inventory. A MAC is trivially spoofed on a shared segment, so binding to one stops nobody who
  is trying, and it is explicitly not an authorization input (ADR-0020 §2). Two tenants may record
  the same address. Supply it in any of `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF` or `aabbccddeeff`;
  it comes back lowercase and colon-separated.
- **Calling it again converges.** The MAC is the one field that moves — swapping the hardware behind
  a name is an inventory change, not a new device.
- **A device gets no DHCP reservation and no substrate DNS name.** Publish whatever name you want in
  your own zone with `records`, above.

`201` with the entry. `400` for a trust class the site does not serve, and the error names the ones
it does.

| Route | Does |
|---|---|
| `GET /v1/tenants/{name}/devices` | the tenant's devices |
| `GET /v1/tenants/{name}/devices/{device}` | one device |
| `DELETE /v1/tenants/{name}/devices/{device}` | deregisters it |

**A registry entry is identity, not authorization.** Registering a device grants it nothing. What a
device is allowed to consume is carried by a credential it proves, at or above the transport layer
(ADR-0020 §2), and that credential is a later layer — this resource issues none. Nor does a device
reach its tenant's network: direct access never grants tenant network membership (ADR-0020 §3).

**A device cannot change trust class.** Its SSID, its VLAN and any later service grants would all
move at once, under an unchanged name. Register it under a new name instead.

**Deregistering does not disconnect.** The device keeps whatever Wi-Fi key it was flashed with,
because that key belongs to the tenant rather than to the device, and revoking it would strand every
other device flashed with it. What deregistration removes is the device's standing to be issued
anything of its own.

**`iot_vendor` devices are registerable.** ADR-0012 §3 refuses them a *broker account*; it does not
refuse them an identity.

**This route needs no wireless controller.** Unlike Wi-Fi keys it writes to no backend, so a site
without a controller still keeps a device registry.

## Wi-Fi keys

A tenant's PPSK key for one IoT trust class (ADR-0012 §3). One key serves every device the tenant
flashes with it; the substrate does not know those devices individually.

`POST /v1/tenants/{name}/wifi-keys`

```json
{ "name": "devices", "trust_class": "iot" }
```

- **The tenant chooses** the key's name and its trust class, and nothing else.
- **The API chooses** the password, and takes the SSID and the VLAN from the trust class. **A tenant
  never picks a VLAN**, which is what keeps a tenant network off the air (ADR-0011 Option B).
- **`ssid` comes back** because a tenant should not hardcode one: the same class is `DVNTM-IOT` at
  mobile and `DVNT-IOT` at home.
- **Calling it again** keeps the key that is already issued. It does not mint a new one — every
  device flashed with the old one would stop associating.
- **`psk` is supplied only to restore** a key the tenant already holds, after the API has lost its
  copy (ADR-0012 §5). The controller is then made to match the devices, rather than the devices
  having to be reflashed. It must be 8 to 63 visible ASCII characters.

`201` with the key and its `psk`. `502` when the controller step fails, with the key in the body —
including its `psk`, so a retry supplies the same one. `400` for a trust class the site does not
serve, and the error names the ones it does.

| Route | Does |
|---|---|
| `GET /v1/tenants/{name}/wifi-keys` | the tenant's keys |
| `GET /v1/tenants/{name}/wifi-keys/{key}` | one key |
| `DELETE /v1/tenants/{name}/wifi-keys/{key}` | revokes it; every device holding it stops associating |

**A read never returns the `psk`.** The holder has it in its own state; what a read says is whether
the key still exists and, through `secrets_stored`, whether the API's copy is still readable. When
`secrets_stored` is `false`, re-`POST` with the `psk` the tenant holds.

**A key cannot change trust class.** That would move every device already holding it onto another
VLAN, silently. Issue a new key instead.

**One oddity you will see in the controller.** The wireless controller refuses to let a PPSK profile
reach zero keys — `delete-psk` answers `errorCode -34044`, *"The PPSK Profile should have at least
one PSK entry"* — even though it will happily *create* a profile with an empty list. So when the
last real key in a profile is revoked, the API leaves one entry named
`DEEVNET-PLACEHOLDER-DO-NOT-USE` behind. Its password is generated, returned to nobody and stored
nowhere, so it cannot be used to join anything, and it is removed again the moment any real key is
issued. It is only ever present when the alternative would be an empty profile.

**The site may serve none of this.** Without `OMADA_API_URL` and `DEEVNET_IOT_TRUST_CLASSES` the API
issues no keys and these routes refuse with a reason — a site with no wireless controller is a
legitimate site.

## Broker accounts

A tenant's MQTT account on the platform broker (ADR-0012 §3, §8, §10; CHG-0016). One account per
thing that connects — a device, or a tenant workload.

`POST /v1/tenants/{name}/broker-accounts`

```json
{
  "name": "lightd",
  "device": "stand-1",
  "publish": ["lightstand/+/scene"],
  "subscribe": ["lightstand/+/state"]
}
```

- **The tenant chooses** the account's name, its topic patterns and, optionally, a device.
- **The API chooses** the password and the username, which is `<tenant>-<name>` and comes back as
  `username`. A tenant can see it without being able to pick it.
- **Patterns are RELATIVE to the tenant.** The API writes the `<tenant>/` itself (§10), so a tenant
  declares `lightstand/+/scene` and never its own name. They come back **absolute**, which is
  deliberately not what went in: what comes back is what the broker will enforce.
  - Naming another tenant does not escape. `tdemo/secrets/#` becomes `eds/tdemo/secrets/#` — a
    topic inside `eds` that happens to be named after someone else, and grants nothing.
  - `#` is allowed and means `eds/#`: the whole of the tenant's own tree, and no more.
  - A pattern that cannot be prefixed into what the tenant meant is `400` — a leading `/`, a `$SYS`
    filter, a `%` (a broker template variable), or a `#` that is not the last level.
- **One direction may be empty.** A sensor only publishes; a collector only subscribes. Requiring
  both would make a tenant declare a pattern it does not need, which grants permission nobody
  wants. **Both empty is `400`**: the account could do nothing.
- **`device` is optional.** Empty means a workload account. A named device must belong to this
  tenant and be in trust class `iot` — `iot_vendor` is refused, because the standard forbids
  `iot_vendor -> iot_backend` and the account could never be used.
- **`log` is reserved** (ADR-0027 §3). The level immediately after the tenant's prefix is where the
  substrate's bridge collects device logs, so a grant there means one thing only:

  | | May publish under `log/` | May subscribe under `log/` |
  |---|---|---|
  | a **device** account | exactly `log/<its own device>` | no — `400` |
  | a **workload** account | no — `400` | yes, its own tenant's |

  A device that could publish under another device's name would write log lines the store cannot
  tell apart afterwards. A workload with logs of its own ships them to `(index, 0)` with the
  tenant's ingest token instead of putting them on the broker.

  **It is the topic space, not the spelling.** `eds/#` and `eds/+/stand-1` reach into the log space
  without naming it, and are refused for a device account just as `log/#` is. `eds/logs/...` is a
  different level and is not affected.
- **Calling it again** keeps the password that is already issued, and returns **no** `password`.
  The API holds a bcrypt hash, not the plaintext (§4), so there is nothing to return and saying so
  beats inventing one.
- **`password` is supplied only to restore** an account the tenant already holds, after the API has
  lost its copy (§5). The broker is then made to match the devices, rather than the devices having
  to be revisited.

`201` with the account and its `password`. `502` when the writer step fails, with the account in
the body — including its `password`, so a retry supplies the same one and does not strand devices
already flashed with the first.

| Route | Does |
|---|---|
| `GET /v1/tenants/{name}/broker-accounts` | the tenant's accounts |
| `GET /v1/tenants/{name}/broker-accounts/{account}` | one account |
| `DELETE /v1/tenants/{name}/broker-accounts/{account}` | revokes it |

**A read never returns the `password`**, and there is no `secrets_stored`: unlike a Wi-Fi key,
the API never holds the plaintext at rest at all. The tenant's own state is the only copy.

**Revocation stops the next connection, not the current one.** The broker caches a connection's
ACLs and evicts on disconnect (§8), so anything connected stays connected until it reconnects.

**How the account reaches the broker.** The broker's auth database is not reachable from the
network. The API sends one request over SSH to a writer on the messaging VM, pinned to a key with
`command=` and `restrict`
(`architecture/substrate/control-plane/broker-account-writer` in `deevnet-docs`). The API never
speaks to the database, and the writer never interprets `SSH_ORIGINAL_COMMAND`.

**The order matters on a retry.** The hash is written to the registry *before* the writer is
called, so a retry after an ambiguous failure sends the same hash and converges. The other order
would mint a new password every retry.

**The site may serve none of this.** Without `DEEVNET_BROKER_WRITER_ADDR` the API issues no broker
accounts and these routes refuse with a reason — a site with no broker is a legitimate site.

## Egress list

`GET /v1/fabric/egress` returns `{"vrfs": [{"tenant": "eds", "vrf": "vrf_eds"}]}` for every `ready`
tenant. The exit node's agent reads it and renders the VRF default routes (ADR-0015 §7).

**Who may call it:** the operator, and the agent token in `DEEVNET_AGENT_TOKEN`. That token reads
this one route and nothing else, so the exit node holds no operator credential. Without
`DEEVNET_AGENT_TOKEN` set, the route is operator-only.

## At rest and in transit

- **At rest.** With OpenBao configured, the TSIG and state-store secrets are stored as Transit
  ciphertext (`vault:v1:…`). A row written before that reads as it is, and is sealed the next time
  it is written.
- **In transit.** The API serves TLS when `DEEVNET_API_TLS_CERT` and `DEEVNET_API_TLS_KEY` are set,
  with a certificate issued by the site CA (OpenBao PKI).
