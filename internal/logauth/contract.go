// Package logauth is the wire contract between the Deevnet API and the log
// store's user writer, and the validation both ends apply to it.
//
// It exists for the same reason brokeracct does: the API produces these
// requests and the writer consumes them, and a contract defined twice is a
// contract that drifts. Nothing here imports the API's service packages, so
// the writer stays a small binary on the observability store rather than the
// whole API.
//
// One difference from brokeracct is worth stating, because it changes what
// this boundary is worth protecting: a broker account crosses as a bcrypt
// hash, so the writer never learns a password. A vmauth user cannot work that
// way - vmauth compares the bearer token it was configured with - so the
// tokens cross in the clear and the writer is as sensitive as the store's own
// configuration file. That is why it runs as its own user, reads a fixed
// config path, and is reached only through a key pinned with command=,
// restrict and from= (ADR-0027, CHG-0020).
package logauth

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Version is the only wire version this code speaks. The API and the writer are
// deployed separately - the API in a container, the writer as a host binary on
// another VM - so a mismatch is a real possibility and guessing at it would be
// worse than refusing.
const Version = 1

// Operations.
const (
	OpPut    = "put"
	OpDelete = "delete"
)

// Bounds. The writer reads from a network peer, so every field is bounded.
const (
	// MaxRequestBytes caps what the writer will read from stdin at all.
	MaxRequestBytes = 64 << 10

	maxTenant = 8 // ADR-0002: a tenant name is a PVE SDN zone id

	// MinTokenLen is 32 characters. The API issues 64 hex characters; the
	// minimum is stated so a short token cannot be written by a caller that
	// was built against a different idea of "token".
	MinTokenLen = 32
	MaxTokenLen = 128

	// MaxIndex is ADR-0002's ceiling: indexes run 1..62 for tenants and 63 is
	// the drill index. 0 is the substrate partition and is never a tenant.
	MaxIndex = 63
)

// Request is one operation on one tenant's users.
//
// The partition numbers are NOT sent. They are derived from the index at both
// ends (see Partitions), because a caller that could name a partition could
// name another tenant's.
type Request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	Tenant  string `json:"tenant"`
	Index   int    `json:"index"`

	// IngestToken writes the tenant's own partition. Empty for a delete.
	IngestToken string `json:"ingest_token,omitempty"`
	// ReadToken reads the tenant's partitions. Empty for a delete.
	ReadToken string `json:"read_token,omitempty"`
}

// Response is the single answer. The writer prints exactly one of these and
// exits non-zero whenever OK is false.
type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Message string `json:"error,omitempty"`

	// Existed reports whether this tenant already had users, which makes a
	// retry distinguishable from a first write in the audit trail without
	// changing the outcome.
	Existed bool `json:"existed,omitempty"`
}

var (
	tenantRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`)
	// A token is opaque to this contract, but it ends up inside a YAML
	// document, so the characters that could end the scalar early are refused
	// rather than escaped. The API issues hex, which is well inside this.
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// Partitions are derived, never accepted.
//
// ProjectID 0 is what the tenant's own workloads ship, 1 is what the substrate
// publishes about the tenant, and 2 is its devices' logs arriving over MQTT
// (ADR-0027 §2). The tenant writes only 0 and reads all three.
func (r Request) IngestPartition() (account, project int) { return r.Index, 0 }
func (r Request) ReadPartitions() [][2]int {
	return [][2]int{{r.Index, 0}, {r.Index, 1}, {r.Index, 2}}
}

// DevicePartition is where the MQTT bridge's messages for this tenant land.
// The bridge holds one token for every tenant and selects between them with a
// header; vmauth matches that header and then overwrites the partition headers
// with these values, so the bridge can only select among tenants the API has
// written (ADR-0027, open question 1).
func (r Request) DevicePartition() (account, project int) { return r.Index, 2 }

// Usernames are derived from the tenant name, so two tenants cannot collide and
// a caller cannot claim another tenant's user by asking for its name.
func (r Request) IngestUser() string { return "ingest-" + r.Tenant }
func (r Request) ReadUser() string   { return "read-" + r.Tenant }

// BridgeRoute is the name of this tenant's routing entry on the shared bridge
// user, and the value the bridge sets in its tenant header.
func (r Request) BridgeRoute() string { return r.Tenant }

// Decode reads one request, refusing anything oversized or carrying a field
// this version does not know.
//
// Unknown fields are an error rather than ignored: a caller sending a field the
// writer silently drops believes something happened that did not, and here that
// something would be a credential.
func Decode(rd io.Reader) (Request, error) {
	dec := json.NewDecoder(io.LimitReader(rd, MaxRequestBytes+1))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("decoding request: %w", err)
	}
	// One request and one answer: trailing content means the caller is speaking
	// a protocol this is not.
	if dec.More() {
		return Request{}, fmt.Errorf("decoding request: trailing content after the request")
	}
	return req, nil
}

// Validate applies every rule the writer will rely on. The API calls it too,
// before sending, so a bad request is a 400 from the API rather than a 502 from
// the far end.
func (r Request) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("unsupported version %d, this writer speaks %d", r.Version, Version)
	}
	switch r.Op {
	case OpPut, OpDelete:
	default:
		return fmt.Errorf("unknown op %q", r.Op)
	}
	if len(r.Tenant) > maxTenant || !tenantRE.MatchString(r.Tenant) {
		return fmt.Errorf("tenant %q is not a tenant name", r.Tenant)
	}
	if r.Index < 1 || r.Index > MaxIndex {
		return fmt.Errorf("index %d is outside 1..%d; 0 is the substrate partition and is never a tenant", r.Index, MaxIndex)
	}
	if r.Op == OpDelete {
		// A delete carries identity only. Tokens on a delete would mean the
		// caller thinks it is removing one particular credential, which this
		// operation does not do: it removes the tenant's users.
		if r.IngestToken != "" || r.ReadToken != "" {
			return fmt.Errorf("a delete carries no tokens")
		}
		return nil
	}
	if err := validToken("ingest_token", r.IngestToken); err != nil {
		return err
	}
	if err := validToken("read_token", r.ReadToken); err != nil {
		return err
	}
	// Two users sharing a token would make the read user a writer, or the
	// other way round, depending on which entry vmauth matched first.
	if r.IngestToken == r.ReadToken {
		return fmt.Errorf("the ingest and read tokens are the same value")
	}
	return nil
}

func validToken(field, tok string) error {
	switch {
	case len(tok) < MinTokenLen:
		return fmt.Errorf("%s is shorter than %d characters", field, MinTokenLen)
	case len(tok) > MaxTokenLen:
		return fmt.Errorf("%s is longer than %d characters", field, MaxTokenLen)
	case !tokenRE.MatchString(tok):
		return fmt.Errorf("%s contains characters this writer will not put in a config file", field)
	case strings.TrimSpace(tok) != tok:
		return fmt.Errorf("%s has surrounding whitespace", field)
	}
	return nil
}
