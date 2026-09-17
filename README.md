# deevnet-provisioning-api

The Deevnet API: the provisioning service behind the `deevnet/deevnet` Terraform provider
([ADR-0012](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/0012-iot-platform-api/)).
Tenants create themselves, and later declare devices and bindings, in their own Terraform. The API
applies that to the substrate services that implement it.

The repository is `deevnet-provisioning-api`; the service it builds, and its binary, image and
container, are `deevnet-api`.

**Tenants are served.** The API creates, restores and deletes tenants
([ADR-0015](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/0015-tenant-onboarding-through-api/)):
- it allocates the index against its registry and the live fabric
- it ensures the tenant's DNS zones and TSIG key, the core router's delegation, and the state-store
  user
- it builds the tenant's network on the fabric, its workloads, and their names
- it returns every value and secret the tenant needs

The IoT resources of ADR-0012 arrive later; their routes still answer `501`. The full contract is
[docs/api-v1.md](docs/api-v1.md).

## Endpoints

| Method and path | Auth | Answer |
|---|---|---|
| `GET /healthz` | none | `200 {"status":"ok"}`. Liveness only; never touches the database. |
| `GET /readyz` | none | `200` when the database answers and is migrated, `503` otherwise. The reason is logged, not returned. |
| `GET /version` | none | `{"version","commit","built"}`, stamped at build time |
| `POST /v1/admissions` | operator | admit a tenant name; returns a single-use enrollment token |
| `POST /v1/tenants` | operator, enrollment token, or the tenant itself | create, restore or resume a tenant |
| `GET /v1/tenants` | operator | the registry, without secrets |
| `GET /v1/tenants/{name}` | operator or the tenant | one tenant, without secrets |
| `POST /v1/tenants/{name}/reconcile` | operator | re-ensure every backend |
| `DELETE /v1/tenants/{name}` | operator or the tenant | remove a tenant whose fabric resources are gone |
| `POST /v1/tenants/{name}/workloads` | operator or the tenant | build a VM in the tenant's network |
| `GET`, `DELETE` `/v1/tenants/{name}/workloads[/{workload}]` | operator or the tenant | list, read, remove |
| `PUT`, `GET`, `DELETE` `/v1/tenants/{name}/records[/{record}]` | operator or the tenant | names beside the workloads' own |
| `GET /v1/fabric/egress` | operator or the egress agent | the VRFs the exit node routes |
| any other `/v1/*` | operator or a tenant | `401` without a valid token; `501` with one |

## Configuration

Environment only.

| Variable | Required | Meaning |
|---|---|---|
| `DEEVNET_API_TOKEN` | yes | The operator bearer token for `/v1`. The API refuses to start without one. |
| `DEEVNET_AGENT_TOKEN` | no | The exit node's egress agent. It reads `GET /v1/fabric/egress` and nothing else. |
| `DATABASE_URL` | yes | PostgreSQL connection string. The schema is migrated on start. |
| `DEEVNET_API_LISTEN` | no | Listen address, default `:8080` |

**Tenants are served when `DEEVNET_SITE` is set.** Then every variable below is required, and the
API refuses to start if any is empty.

| Variable | Mobile value | Meaning |
|---|---|---|
| `DEEVNET_SITE` | `mobile` | site label in zone names |
| `DEEVNET_SITE_OCTET` | `20` | second octet of the site block |
| `DEEVNET_ROOT_DOMAIN` | `deevnet.net` | |
| `DEEVNET_VRF_VNI_BASE`, `DEEVNET_VNET_VNI_BASE` | `10000`, `20000` | ADR-0002 bases |
| `DEEVNET_FABRIC_CONTROLLER`, `DEEVNET_FABRIC_NODE` | `evpn1`, `dv02hyp002p02` | the attachment every tenant gets |
| `DEEVNET_DNS_UPDATE_SERVER` | `tdns.mobile.deevnet.net` | where tenants send RFC 2136 updates |
| `DEEVNET_DNS_APEX_NS` | `dv02idn001v01.mobile.deevnet.net` | apex NS and SOA primary (ADR-0005) |
| `DEEVNET_DNS_UPDATE_FROM` | `10.20.99.0/24,10.20.10.0/24,10.20.50.0/24` | networks that may attempt an update |
| `DEEVNET_STATE_ENDPOINT`, `DEEVNET_STATE_BUCKET` | `http://tfstate.mobile.deevnet.net:9000`, `tf-state` | the offered state store |
| `DEEVNET_RESOLVER_FORWARD_TO` | `10.20.25.21` | the address the router forwards tenant zones to |
| `POWERDNS_API_URL` | `http://10.20.25.21:8081` | PowerDNS HTTP API |
| `OPNSENSE_API_URL` | `https://10.20.25.1/api` | the core router |
| `MINIO_ADMIN_ENDPOINT` | `10.20.25.20:9000` | the state store's admin API |
| `PROXMOX_API_URL` | `https://10.20.99.22:8006` | the tenant hypervisor |
| `DEEVNET_TENANT_VMID_BASE` | `2000` | first VMID of the tenant band |
| `DEEVNET_MAC_NAMESPACE` | `02:de:20` | a workload's MAC derives from its VMID |
| `DEEVNET_TEMPLATE_PREFIX` | `fedora-server-` | the newest match is cloned |
| `DEEVNET_TENANT_STORAGE`, `DEEVNET_TENANT_DISK` | `local-lvm`, `scsi0` | where a workload lands, and the disk grown |
| `DEEVNET_TENANT_CIUSER` | `a_autoprov` | the cloud-init account the tenant's keys go to |

**Backend credentials come from OpenBao** (ADR-0016) when `OPENBAO_ADDR` is set: the fields of one
KV v2 secret.
- **Fields:** `powerdns_api_key`, `opnsense_api_key`, `opnsense_api_secret`,
  `minio_admin_access_key`, `minio_admin_secret_key`, `proxmox_token_id`, `proxmox_token_secret`,
  and `token_hmac_key` (base64, at least 32 bytes, the MAC key of tenant tokens).
- **OpenBao also provides** envelope encryption of stored secrets and enrollment tokens.
- **Without OpenBao** (tests and local runs), the same names are read from the environment in upper
  case. There is then no enrollment and no encryption at rest.

| Variable | Default | Meaning |
|---|---|---|
| `OPENBAO_ADDR` | | e.g. `https://10.20.25.21:8200`; turns OpenBao on |
| `OPENBAO_CACERT` | | the pinned listener certificate |
| `OPENBAO_ROLE_ID`, `OPENBAO_SECRET_ID` | | the API's AppRole |
| `OPENBAO_KV_MOUNT`, `OPENBAO_KV_PATH` | `deevnet-api`, `backends` | where the credentials are |
| `OPENBAO_TRANSIT_KEY` | `tenant-secrets` | the key that seals stored secrets |
| `DEEVNET_ENROLLMENT_TTL` | `72h` | how long an enrollment token lives |
| `DEEVNET_API_TLS_CERT`, `DEEVNET_API_TLS_KEY` | | serve TLS; set both or neither |
| `OPNSENSE_INSECURE_TLS`, `PROXMOX_INSECURE_TLS` | `true` | self-signed certificates on those devices |
| `MINIO_ADMIN_TLS` | `false` | |

## Build and stage

Run on the Builder (`dv00bld001p01`), which serves container images to the automation.

```bash
make test               # go test ./...  (store and backend tests skip without their services)
make test-integration   # the same, against throwaway PostgreSQL, PowerDNS and MinIO containers
make image              # podman build localhost/deevnet-api:<git describe>
git tag v0.1.0
make stage              # save to /srv/deevnet-http/container-images/deevnet-api/ (sudo)
```

`make stage` refuses an untagged or dirty tree, so a staged image always maps to a commit.

## Deployment

The `deevnet.mgmt` collection's `deevnet_api` role pushes the staged tarball to the provisioning
VM (`dv02prv001v01`, Platform VLAN 25), loads it, and runs the API beside its PostgreSQL container
on a private podman network. The database publishes no port. Pin the image tag in the role's
defaults, or in inventory, when a new version is staged.

## Layout

```
cmd/deevnet-api/        main and configuration: pool, migrations, backends, graceful shutdown
internal/server/        routes and handlers
internal/auth/          bearer token parsing
internal/openbao/       KV, Transit and response wrapping over OpenBao's HTTP API
internal/tenant/        ADR-0015's rules: allocation, restore, the backend step order
internal/tenant/tenanttest/  in-memory registry and backends for tests
internal/store/         the registry in PostgreSQL, with embedded migrations
internal/backend/       powerdns (zones, keys, records), opnsense (the resolver), minio (state store), proxmox (fabric, networks, workloads)
docs/api-v1.md          the tenant API contract
Containerfile           multi-stage build to a static, non-root distroless image
```
