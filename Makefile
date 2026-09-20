PKG     := github.com/deevnet/deevnet-provisioning-api
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

IMAGE   ?= localhost/deevnet-api

# Where the Builder's nginx serves container images from (deevnet.builder
# artifacts role, nginx_artifacts_root). Same layout fetch_podman_images.yml
# writes for upstream images, so deevnet.mgmt pushes this one the same way.
ARTIFACTS_ROOT ?= /srv/deevnet-http
STAGE_DIR      := $(ARTIFACTS_ROOT)/container-images/deevnet-api
TARBALL        := deevnet-api-$(VERSION).tar

# The broker account writer is a HOST binary, not a container: it runs on the
# messaging VM beside a PostgreSQL bound to loopback, which is the whole point
# of CHG-0016's option C. So it is staged as a plain binary and the vernemq
# role copies it, rather than being loaded as an image.
WRITER          := deevnet-broker-account
WRITER_STAGE    := $(ARTIFACTS_ROOT)/binaries/$(WRITER)
WRITER_FILE     := $(WRITER)-$(VERSION)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Built=$(BUILT)

.PHONY: default help test test-integration vet build build-writer image stage stage-writer clean

default: help

help:
	@echo "Targets:"
	@echo "  test    go test ./..."
	@echo "  test-integration"
	@echo "          the same tests against throwaway PostgreSQL, PowerDNS and MinIO containers"
	@echo "  vet     go vet ./..."
	@echo "  build   static binary in bin/"
	@echo "  build-writer"
	@echo "          the broker account writer, a host binary for the messaging VM"
	@echo "  stage-writer"
	@echo "          build-writer, then install it under $(ARTIFACTS_ROOT)/binaries (sudo)"
	@echo "  image   podman build $(IMAGE):$(VERSION)"
	@echo "  stage   image, then save it under $(STAGE_DIR) (sudo)"
	@echo "  clean   remove bin/"
	@echo ""
	@echo "VERSION=$(VERSION)"

test:
	go test ./...

# Throwaway backends on loopback, from the same images the substrate runs, so
# the store and backend tests exercise real software rather than fakes. The
# images come from the Builder's image store when they are not already loaded.
# Nothing here touches the site: the router and Proxmox tests stay skipped
# unless their DEEVNET_TEST_* variables are set by hand, and those only read.
IT_PREFIX    := deevnet-api-it
IT_IMAGES    := $(ARTIFACTS_ROOT)/container-images
IT_PG        := docker.io/library/postgres:17.11
IT_PDNS      := docker.io/powerdns/pdns-auth-49:4.9.17
IT_MINIO     := quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z

test-integration:
	@podman image exists $(IT_PG)    || podman load -q -i $(IT_IMAGES)/postgres/postgres-17.11.tar
	@podman image exists $(IT_PDNS)  || podman load -q -i $(IT_IMAGES)/pdns-auth/pdns-auth-4.9.17.tar
	@podman image exists $(IT_MINIO) || podman load -q -i $(IT_IMAGES)/minio/minio-RELEASE.2025-09-07T16-13-09Z.tar
	@podman rm -f $(IT_PREFIX)-pg $(IT_PREFIX)-pdns $(IT_PREFIX)-minio >/dev/null 2>&1 || true
	podman run -d --name $(IT_PREFIX)-pg -p 127.0.0.1:25432:5432 \
	  -e POSTGRES_DB=it -e POSTGRES_USER=it -e POSTGRES_PASSWORD=it $(IT_PG) >/dev/null
	podman run -d --name $(IT_PREFIX)-pdns -p 127.0.0.1:28081:8081 $(IT_PDNS) \
	  --local-port=5353 --api=yes --api-key=it --webserver=yes \
	  --webserver-address=0.0.0.0 --webserver-allow-from=0.0.0.0/0 --dnsupdate=yes \
	  "--default-soa-content=dv02idn001v01.mobile.deevnet.net hostmaster.@ 0 10800 3600 604800 3600" >/dev/null
	podman run -d --name $(IT_PREFIX)-minio -p 127.0.0.1:29000:9000 \
	  -e MINIO_ROOT_USER=it-root -e MINIO_ROOT_PASSWORD=it-root-secret $(IT_MINIO) server /data >/dev/null
	@for i in $$(seq 1 30); do podman exec $(IT_PREFIX)-pg pg_isready -U it -d it >/dev/null 2>&1 && break; sleep 1; done
	@sleep 3
	DEEVNET_TEST_DATABASE_URL='postgres://it:it@127.0.0.1:25432/it?sslmode=disable' \
	DEEVNET_TEST_PDNS_URL=http://127.0.0.1:28081 DEEVNET_TEST_PDNS_KEY=it \
	DEEVNET_TEST_MINIO_ENDPOINT=127.0.0.1:29000 \
	DEEVNET_TEST_MINIO_ACCESS_KEY=it-root DEEVNET_TEST_MINIO_SECRET_KEY=it-root-secret \
	go test -count=1 -p 1 ./... ; rc=$$?; \
	podman rm -f $(IT_PREFIX)-pg $(IT_PREFIX)-pdns $(IT_PREFIX)-minio >/dev/null; exit $$rc

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/deevnet-api ./cmd/deevnet-api

# Static and CGO-free so it does not care what is installed on the messaging
# VM. It is invoked by sshd as a forced command, once per request, so startup
# cost matters more than anything it would gain from dynamic linking.
build-writer:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(WRITER) ./cmd/$(WRITER)

image:
	podman build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILT=$(BUILT) \
	  -t $(IMAGE):$(VERSION) \
	  -f Containerfile .

# A dirty tree is refused: a staged image has to be reproducible from a commit.
stage: image
	@case "$(VERSION)" in *-dirty|dev) echo "refusing to stage VERSION=$(VERSION); commit and tag first" >&2; exit 1;; esac
	@mkdir -p bin
	@# podman save refuses to write over an existing archive.
	rm -f bin/$(TARBALL)
	podman save -o bin/$(TARBALL) $(IMAGE):$(VERSION)
	sudo install -d -o nginx -g nginx -m 0755 $(STAGE_DIR)
	sudo install -o nginx -g nginx -m 0644 bin/$(TARBALL) $(STAGE_DIR)/$(TARBALL)
	sudo ln -sfn $(TARBALL) $(STAGE_DIR)/deevnet-api-latest.tar
	@echo "staged $(STAGE_DIR)/$(TARBALL)"

# Same refusal as stage, and for the same reason: what runs on a host has to be
# traceable to a commit.
stage-writer: build-writer
	@case "$(VERSION)" in *-dirty|dev) echo "refusing to stage VERSION=$(VERSION); commit and tag first" >&2; exit 1;; esac
	sudo install -d -o nginx -g nginx -m 0755 $(WRITER_STAGE)
	sudo install -o nginx -g nginx -m 0644 bin/$(WRITER) $(WRITER_STAGE)/$(WRITER_FILE)
	sudo ln -sfn $(WRITER_FILE) $(WRITER_STAGE)/$(WRITER)-latest
	@echo "staged $(WRITER_STAGE)/$(WRITER_FILE)"

clean:
	rm -rf bin
