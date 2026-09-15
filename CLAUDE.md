# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`deevnet-api` is the Deevnet API (ADR-0012 in `deevnet-docs`): a Go HTTP service that tenant
Terraform reaches through the `deevnet/deevnet` provider. It is **provisioning-only**. Nothing at
runtime (devices, brokers, the AP) depends on it being up.

Today it is a shell: health, readiness, version, and a token-gated `/v1` that returns 501.

## Commands

```bash
make test     # go test ./...
make vet      # go vet ./...
make build    # static binary in bin/
make image    # podman build localhost/deevnet-api:<version>
make stage    # save the image under the Builder's artifact root (needs a clean, tagged tree)
```

## Rules that are easy to get wrong

- **Standard library first.** Routing is `net/http`'s `ServeMux` with method patterns. The only
  dependency is `pgx/v5`. Don't add a router or framework to get what the mux already does.
- **Configuration is environment only.** The container has no config file, and secrets arrive
  through a root-only env file written by the `deevnet_api` Ansible role.
- **Never put secrets or connection errors in a response body.** Readiness logs the reason and
  returns a fixed shape; tests assert this.
- **`/healthz` must not touch the database.** It is liveness. Readiness is `/readyz`.
- **Images are pushed, not pulled.** The provisioning VM sits on Platform, which has no route back
  to the Builder's artifact server under the zone policy. `make stage` writes the tarball where
  the role reads it on the control node.
- **Base images are fully qualified** (`docker.io/...`, `gcr.io/...`). Podman refuses short names
  non-interactively.
