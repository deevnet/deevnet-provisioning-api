# deevnet-provisioning-api

The Deevnet API: the provisioning service behind the `deevnet/deevnet` Terraform provider
([ADR-0012](https://deevnet.github.io/deevnet-docs/docs/architecture/decisions/0012-iot-platform-api/)).
Tenants declare devices and bindings in their own Terraform, and the API applies them to the
substrate services that implement them.

The repository is `deevnet-provisioning-api`; the service it builds, and its binary, image and
container, are `deevnet-api`.

**This is the shell.** It serves health, readiness and version, and puts every `/v1` route behind a
bearer token, where each route answers `501 not implemented`. The device registry, Wi-Fi key and
broker account bindings arrive in later iterations.

## Endpoints

| Method and path | Auth | Answer |
|---|---|---|
| `GET /healthz` | none | `200 {"status":"ok"}`. Liveness only; never touches the database. |
| `GET /readyz` | none | `200` when the database answers a ping, `503` otherwise. The reason is logged, not returned. |
| `GET /version` | none | `{"version","commit","built"}`, stamped at build time |
| `/v1/*` | `Authorization: Bearer <token>` | `401` without a valid token; `501` with one |

## Configuration

Environment only.

| Variable | Required | Meaning |
|---|---|---|
| `DEEVNET_API_TOKEN` | yes | The bearer token for `/v1`. The API refuses to start without one. |
| `DATABASE_URL` | yes | PostgreSQL connection string, e.g. `postgres://deevnet_api:…@deevnet-api-db:5432/deevnet_api?sslmode=disable` |
| `DEEVNET_API_LISTEN` | no | Listen address, default `:8080` |

## Build and stage

Run on the Builder (`dv00bld001p01`), which serves container images to the automation.

```bash
make test               # go test ./...
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
cmd/deevnet-api/     main: configuration, database pool, graceful shutdown
internal/server/     routes and handlers
internal/auth/       bearer-token middleware (a stub; per-tenant credentials replace it)
internal/version/    build identity, set with -ldflags
Containerfile        multi-stage build to a static, non-root distroless image
```
