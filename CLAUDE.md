# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`deevnet-provisioning-api` builds the Deevnet API (ADR-0012 and ADR-0015 in `deevnet-docs`): a Go HTTP
service that tenant Terraform reaches through the `deevnet/deevnet` provider. It is
**provisioning-only**. Nothing at runtime (devices, brokers, the AP, tenant workloads) depends on it
being up.

It serves tenants (create, restore, reconcile, delete; `docs/api-v1.md`). The IoT resources still
answer 501.

The repository name says what the service is for; the service itself, its binary, image and
container keep the short name `deevnet-api`, which is what the `deevnet.mgmt` `deevnet_api` role
and the staged image path use.

## Commands

```bash
make test     # go test ./...
make test-integration  # store and backend tests against throwaway PostgreSQL, PowerDNS, MinIO
make vet      # go vet ./...
make build    # static binary in bin/
make image    # podman build localhost/deevnet-api:<version>
make stage    # save the image under the Builder's artifact root (needs a clean, tagged tree)
```

## Rules that are easy to get wrong

- **Standard library first.** Routing is `net/http`'s `ServeMux` with method patterns. The
  dependencies are `pgx/v5` and `madmin-go/v3`, whose admin API encrypts request bodies, which is
  not worth reimplementing. Don't add a router or framework to get what the mux already does.
- **Every backend call is an ensure.** Read, compare, write only the difference, and treat
  "already exists" or "not found" as success where that is the goal. A create that failed half way
  is resumed by calling it again, and existing objects (eds's, from Ansible) are adopted.
- **The tenant's state holds the authoritative secrets** (ADR-0015 §4). Supplied secrets win over
  stored ones; the API token is stored only as a hash.
- **Allocation reads the fabric.** An index is free only if no registry row holds it and no SDN
  zone or VNet carries its numbers. Don't shortcut to the database alone.
- **The Proxmox backend only reads.** The API never writes to a hypervisor; egress is pulled by
  the exit node (ADR-0015 §7).
- **Configuration is environment only.** The container has no config file, and secrets arrive
  through a root-only env file written by the `deevnet_api` Ansible role.
- **Never put secrets or connection errors in a response body.** Readiness logs the reason and
  returns a fixed shape. A failed backend step names the step only; its error goes to the log and
  `tenant_steps`. Secrets appear only in create responses. Tests assert all of this.
- **`/healthz` must not touch the database.** It is liveness. Readiness is `/readyz`.
- **Images are pushed, not pulled.** The provisioning VM sits on Platform, which has no route back
  to the Builder's artifact server under the zone policy. `make stage` writes the tarball where
  the role reads it on the control node.
- **Base images are fully qualified** (`docker.io/...`, `gcr.io/...`). Podman refuses short names
  non-interactively.
