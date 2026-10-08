# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`deevnet-provisioning-api` builds the Deevnet API (ADR-0012 and ADR-0015 in `deevnet-docs`): a Go HTTP
service that tenant Terraform reaches through the `deevnet/deevnet` provider. It is
**provisioning-only**. Nothing at runtime (devices, brokers, the AP, tenant workloads) depends on it
being up.

It serves tenants (create, restore, reconcile, delete), their Wi-Fi keys, their device registry,
their devices' fixed addresses, their MQTT broker accounts, their log store tokens and their Grafana organisation (`api/openapi.yaml`, published at
https://deevnet.github.io/deevnet-provisioning-api/).

The repository name says what the service is for; the service itself, its binary, image and
container keep the short name `deevnet-api`, which is what the `deevnet.mgmt` `deevnet_api` role
and the staged image path use.

## Commands

```bash
make test     # go test ./...
make test-integration  # store and backend tests against throwaway PostgreSQL, PowerDNS, MinIO
make vet      # go vet ./...
make spec-lint  # lint api/openapi.yaml (needs node)
make site     # the documentation site (Hugo) into site/public
make build    # static binary in bin/
make image    # podman build localhost/deevnet-api:<version>
make stage    # save the image under the Builder's artifact root (needs a clean, tagged tree)
make stage-pi # deevnet-kit + deevnet-log-user for linux/arm64, for the image factory's pi-backend image
```

## Rules that are easy to get wrong

- **A route or wire field changes in `api/openapi.yaml` in the same commit.** The spec is written by
  hand and is what the published reference renders. `internal/server/openapi_test.go` fails when a
  `HandleFunc` pattern or a `*Body`/`*View` json field is missing from it, or the reverse; a new wire
  type is added to that test's `wireSchemas` table. Behaviour a field cannot express (who may call,
  status codes, restore rules) goes in the operation's description or a guide under
  `site/content/docs/`.
- **A change someone running or calling the API would notice adds a line to `CHANGELOG.md`**, under
  `## Unreleased`, in the same commit. Tagging renames that heading to `## X.Y.Z (date)`. The site
  renders the file as Release Notes. A new required variable or a changed default goes under
  `### Upgrading`.
- **Standard library first.** Routing is `net/http`'s `ServeMux` with method patterns. The
  dependencies are `pgx/v5` and `madmin-go/v3`, whose admin API encrypts request bodies, which is
  not worth reimplementing. Don't add a router or framework to get what the mux already does.
- **Every backend call is an ensure.** Read, compare, write only the difference, and treat
  "already exists" or "not found" as success where that is the goal. A create that failed half way
  is resumed by calling it again, and existing objects (eds's, from Ansible) are adopted.
- **The tenant's state holds the authoritative secrets** (ADR-0015 §4). Supplied secrets win over
  stored ones; the API token is stored only as a hash.
- **Secrets live in OpenBao** (ADR-0016): backend credentials in KV, stored tenant secrets sealed
  with Transit, enrollment tokens by response wrapping. Env credentials are for tests and local
  runs only. `internal/openbao` is plain net/http on purpose.
- **Tenant tokens verify without the registry.** `dvt1.<tenant>.<nonce>.<mac>`, keyed by
  `token_hmac_key` in OpenBao, so a tenant can restore itself after the database is lost. The
  registry's hash revokes. Don't replace them with random opaque tokens.
- **Allocation reads the fabric.** An index is free only if no registry row holds it and no SDN
  zone or VNet carries its numbers. Don't shortcut to the database alone.
- **A workload's identity is derived, never allocated by hand** (ADR-0015 §12): ordinal from the
  store, then VMID, MAC and address from it. Re-applying a workload keeps all four.
- **SDN apply is cluster-wide**, so the service holds one lock across tenants while it applies.
- **Proxmox answers 500, not 404, for an absent SDN object.** The client reads "does not exist" in
  a 500 body as not-found; don't "fix" that by trusting the status alone.
- **Egress stays pulled by the exit node** (ADR-0015 §7): the API writes SDN and VMs through the
  PVE API, never files on a hypervisor.
- **Configuration is environment only.** The container has no config file, and secrets arrive
  through a root-only env file written by the `deevnet_api` Ansible role.
- **Never put secrets or connection errors in a response body.** Readiness logs the reason and
  returns a fixed shape. A failed backend step names the step only; its error goes to the log and
  `tenant_steps`. Secrets appear only in create and restore responses - and the log tokens and the
  dashboard password also on a reconcile, because unlike the API token they are readable and a tenant
  created before the store existed has to be handed them somehow. Tests assert all of this.
- **Dashboard data sources have fixed UIDs** (`internal/backend/grafana.DataSources`), the same in
  every tenant's organisation and on the Pi. A dashboard names them; changing one breaks every
  tenant's dashboards. The tenant login is an Editor, never Admin: an Admin can create a data
  source, which is a URL Grafana's server requests for it.
- **Grafana 13 quirks the client is built around** (verified against 13.2.2 by
  `make test-integration`): `users.auto_assign_org` must stay ON or `OrgId` on user create is ignored
  and a personal organisation named for the login is made; `DELETE /api/orgs/<id>` answers 500
  (grafana/grafana#127386), so Remove renames the emptied organisation instead.
- **The router's DHCP reservations have two writers.** Inventory's rows start "Ansible managed", the
  API's "Deevnet API - ", and each leaves the other's alone. The Kea client finds its own row by its
  exact description and refuses a MAC or address any other row on the subnet holds. Don't key it by
  MAC: that is how one writer overwrites the other.
- **A device address is allocated, not derived**, unlike a workload's: the device network is one
  subnet shared by every tenant. The tenant's state remembers it and re-requests it on a restore, and
  a clash never says who holds what.
- **`/healthz` must not touch the database.** It is liveness. Readiness is `/readyz`.
- **Two writers, two hosts, two keys.** Broker accounts go to the messaging VM as a bcrypt hash;
  log tokens go to the observability store as the token itself, because vmauth compares what it was
  configured with. Both are one request and one answer to a program pinned with `command=`. Neither
  key may be reused for the other.
- **The log store's `auth.yml` has two authors.** Ansible owns `base.json`, the writer owns
  `users.d/<tenant>.json`, and `deevnet-log-user` renders the file from both. Don't make either side
  write `auth.yml` directly.
- **`cmd/deevnet-kit` is the API's stand-in on a take-home Pi** (Mosquitto, VictoriaLogs, vmauth, the
  log bridge). It lives here so it imports `brokeracct` and `tenant` rather than copying their rules,
  and it has `deevnet-log-user` render vmauth's users. A rule change in either package changes the
  Pi too; that is the point. It is not part of the deployed API.
- **Images are pushed, not pulled.** The provisioning VM sits on Platform, which has no route back
  to the Builder's artifact server under the zone policy. `make stage` writes the tarball where
  the role reads it on the control node.
- **Base images are fully qualified** (`docker.io/...`, `gcr.io/...`). Podman refuses short names
  non-interactively.
