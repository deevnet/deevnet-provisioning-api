# Built by `make image`; the Makefile passes the build arguments.
#
# Base images are fully qualified: podman refuses short names when it cannot
# prompt, which is every non-interactive build.

ARG GO_VERSION=1.25.9

FROM docker.io/library/golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/deevnet/deevnet-provisioning-api/internal/version.Version=${VERSION} \
        -X github.com/deevnet/deevnet-provisioning-api/internal/version.Commit=${COMMIT} \
        -X github.com/deevnet/deevnet-provisioning-api/internal/version.Built=${BUILT}" \
      -o /out/deevnet-api ./cmd/deevnet-api

# Static binary, no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/deevnet-api /usr/local/bin/deevnet-api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/deevnet-api"]
