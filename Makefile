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

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Built=$(BUILT)

.PHONY: default help test vet build image stage clean

default: help

help:
	@echo "Targets:"
	@echo "  test    go test ./..."
	@echo "  vet     go vet ./..."
	@echo "  build   static binary in bin/"
	@echo "  image   podman build $(IMAGE):$(VERSION)"
	@echo "  stage   image, then save it under $(STAGE_DIR) (sudo)"
	@echo "  clean   remove bin/"
	@echo ""
	@echo "VERSION=$(VERSION)"

test:
	go test ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/deevnet-api ./cmd/deevnet-api

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
	podman save -o bin/$(TARBALL) $(IMAGE):$(VERSION)
	sudo install -d -o nginx -g nginx -m 0755 $(STAGE_DIR)
	sudo install -o nginx -g nginx -m 0644 bin/$(TARBALL) $(STAGE_DIR)/$(TARBALL)
	sudo ln -sfn $(TARBALL) $(STAGE_DIR)/deevnet-api-latest.tar
	@echo "staged $(STAGE_DIR)/$(TARBALL)"

clean:
	rm -rf bin
