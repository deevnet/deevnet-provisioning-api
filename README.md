# deevnet-provisioning-api

The Deevnet API: the provisioning service behind the `deevnet/deevnet` Terraform provider
([ADR-0012](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0012-iot-platform-api/)).
Tenants create themselves, and later declare devices and bindings, in their own Terraform. The API
applies that to the substrate services that implement it.

The repository is `deevnet-provisioning-api`; the service it builds, and its binary, image and
container, are `deevnet-api`.

**Tenants are served.** The API creates, restores and deletes tenants
([ADR-0015](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/tenant-model/0015-tenant-onboarding-through-api/)):
- it allocates the index against its registry and the live fabric
- it ensures the tenant's DNS zones and TSIG key, the core router's delegation, and the state-store
  user
- it builds the tenant's network on the fabric, its workloads, and their names
- it returns every value and secret the tenant needs

It also serves a tenant's device registry, fixed device addresses, Wi-Fi keys, MQTT broker
accounts, log store tokens and dashboard login, each where the site runs the service behind it.

## Documentation

**https://deevnet.github.io/deevnet-provisioning-api/** is the reference and the guides.

| | |
|---|---|
| [API Reference](https://deevnet.github.io/deevnet-provisioning-api/docs/reference/) | every route, request and response, rendered from `api/openapi.yaml` |
| [Authentication](https://deevnet.github.io/deevnet-provisioning-api/docs/authentication/) | the four kinds of token and what each may call |
| [Tenant Lifecycle](https://deevnet.github.io/deevnet-provisioning-api/docs/tenant-lifecycle/) | admit, create, restore, resume, reconcile, delete |
| [Device Services](https://deevnet.github.io/deevnet-provisioning-api/docs/device-services/) | registry, fixed addresses, Wi-Fi keys, broker accounts |
| [Conventions](https://deevnet.github.io/deevnet-provisioning-api/docs/conventions/) | ensures, partial objects, where secrets appear, errors |
| [Configuration](https://deevnet.github.io/deevnet-provisioning-api/docs/configuration/) | every environment variable the service reads |
| [Release Notes](https://deevnet.github.io/deevnet-provisioning-api/docs/release-notes/) | what changed in each version; the source is `CHANGELOG.md` |

`api/openapi.yaml` (OpenAPI 3.1) is the contract, written by hand. `internal/server/openapi_test.go`
fails when it and the code disagree on a route or a wire field, so a route or field change is made
in both in the same commit. `make spec-lint` checks the document itself. `site/` is the Hugo site
that publishes it; `make site-serve` runs it locally.

A site's own configuration values are rendered by the `deevnet.mgmt` collection's `deevnet_api` role
from inventory.

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
api/openapi.yaml        the API contract (OpenAPI 3.1)
cmd/deevnet-api/        main and configuration: pool, migrations, backends, graceful shutdown
cmd/deevnet-broker-account/  the broker account writer, a host binary for the messaging VM
cmd/deevnet-log-user/   the log store's user writer, a host binary for the observability store
cmd/deevnet-kit/        the API's stand-in on a take-home Raspberry Pi
internal/server/        routes, handlers, and the tests that hold the spec to them
internal/auth/          bearer token parsing
internal/openbao/       KV, Transit and response wrapping over OpenBao's HTTP API
internal/tenant/        ADR-0015's rules: allocation, restore, the backend step order
internal/tenant/tenanttest/  in-memory registry and backends for tests
internal/store/         the registry in PostgreSQL, with embedded migrations
internal/backend/       powerdns, opnsense (resolver and DHCP reservations), minio (state store),
                        proxmox (fabric, networks, workloads), omada (Wi-Fi keys), grafana
                        (dashboards), brokerwriter and logwriter (the two SSH writers)
internal/brokeracct/, internal/logauth/  the wire contracts the API shares with its two writers
site/                   the documentation site (Hugo)
Containerfile           multi-stage build to a static, non-root distroless image
```
