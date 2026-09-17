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
- it returns every value and secret the tenant needs

The IoT resources of ADR-0012 arrive later; their routes still answer `501`. The full contract is
[docs/api-v1.md](docs/api-v1.md).

## Endpoints

| Method and path | Auth | Answer |
|---|---|---|
| `GET /healthz` | none | `200 {"status":"ok"}`. Liveness only; never touches the database. |
| `GET /readyz` | none | `200` when the database answers and is migrated, `503` otherwise. The reason is logged, not returned. |
| `GET /version` | none | `{"version","commit","built"}`, stamped at build time |
| `POST /v1/tenants` | operator token | create, restore or resume a tenant |
| `GET /v1/tenants`, `GET /v1/tenants/{name}` | operator token | the registry, without secrets |
| `POST /v1/tenants/{name}/reconcile` | operator token | re-ensure every backend |
| `DELETE /v1/tenants/{name}` | operator token | remove a tenant whose fabric resources are gone |
| `GET /v1/fabric/egress` | operator token | the VRFs the exit node routes |
| any other `/v1/*` | operator token | `401` without a valid token; `501` with one |

## Configuration

Environment only.

| Variable | Required | Meaning |
|---|---|---|
| `DEEVNET_API_TOKEN` | yes | The operator bearer token for `/v1`. The API refuses to start without one. |
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
| `POWERDNS_API_URL`, `POWERDNS_API_KEY` | `http://10.20.25.21:8081` | PowerDNS HTTP API |
| `OPNSENSE_API_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` | `https://10.20.25.1/api` | the core router |
| `MINIO_ADMIN_ENDPOINT`, `MINIO_ADMIN_ACCESS_KEY`, `MINIO_ADMIN_SECRET_KEY` | `10.20.25.20:9000` | the API's own state-store admin user, never root |
| `PROXMOX_API_URL`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET` | `https://10.20.99.22:8006` | a token that can read SDN |
| `OPNSENSE_INSECURE_TLS`, `PROXMOX_INSECURE_TLS` | optional, default `true` | self-signed certificates until the internal CA |
| `MINIO_ADMIN_TLS` | optional, default `false` | |

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
internal/auth/          operator bearer-token middleware
internal/tenant/        ADR-0015's rules: allocation, restore, the backend step order
internal/tenant/tenanttest/  in-memory registry and backends for tests
internal/store/         the registry in PostgreSQL, with embedded migrations
internal/backend/       powerdns, opnsense (the resolver), minio (state store), proxmox (fabric, read-only)
docs/api-v1.md          the tenant API contract
Containerfile           multi-stage build to a static, non-root distroless image
```
