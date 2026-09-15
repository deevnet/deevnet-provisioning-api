// Package version holds build identity, set at link time:
//
//	go build -ldflags "-X github.com/deevnet/deevnet-api/internal/version.Version=v0.1.0 ..."
//
// The defaults are what an unstamped `go run` reports, so a binary that says
// "dev" was never built by the Makefile or the Containerfile.
package version

var (
	Version = "dev"
	Commit  = "unknown"
	Built   = "unknown"
)
