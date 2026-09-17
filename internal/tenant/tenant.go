package tenant

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Status is where a tenant is in its lifecycle.
type Status string

const (
	// StatusProvisioning: the row exists and at least one backend step has not
	// yet succeeded. Calling create again resumes it.
	StatusProvisioning Status = "provisioning"
	// StatusReady: every backend step succeeded.
	StatusReady Status = "ready"
	// StatusDeleting: removal started and did not finish. Calling delete again
	// resumes it.
	StatusDeleting Status = "deleting"
)

// The backend steps, in the order create runs them. Delete runs them in reverse.
const (
	StepDNS      = "dns"
	StepResolver = "resolver"
	StepState    = "state"
)

// Secrets are what the API keeps for a tenant. The TSIG and state secrets are
// kept usable because the API has to re-ensure them after a backend rebuild;
// the API token is kept only as a hash.
type Secrets struct {
	TSIG         string
	State        string
	APITokenHash []byte
}

// Step is the last recorded outcome of one backend step.
type Step struct {
	Name      string    `json:"name"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Record is a tenant as the registry holds it.
type Record struct {
	Name      string
	Index     int
	Status    Status
	Secrets   Secrets
	Steps     []Step
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AuditEntry is one line of the audit log: who did what to which tenant.
type AuditEntry struct {
	Actor  string
	Action string
	Tenant string
	Detail map[string]any
}

// Store is the registry (ADR-0015 §1).
type Store interface {
	Get(ctx context.Context, name string) (Record, error)
	List(ctx context.Context) ([]Record, error)

	// Create inserts a tenant. It holds the allocation lock while it calls pick
	// with the indexes rows already hold (index -> tenant name), and stores the
	// index pick returns, so two creates can never take the same index. It
	// returns ErrExists if the name is already registered.
	Create(ctx context.Context, name string, secrets Secrets, pick func(held map[int]string) (int, error)) (Record, error)

	SetStatus(ctx context.Context, name string, status Status) error
	SetSecrets(ctx context.Context, name string, secrets Secrets) error
	RecordStep(ctx context.Context, name, step string, stepErr error) error
	Delete(ctx context.Context, name string) error

	Audit(ctx context.Context, e AuditEntry) error
}

// DNSTenant is everything tenant DNS needs for one tenant (ADR-0004, ADR-0005).
type DNSTenant struct {
	KeyName    string
	Algorithm  string
	Secret     string
	Zones      []string
	ApexNS     string
	UpdateFrom []string
}

// DNS is the tenant DNS server.
type DNS interface {
	// Ensure makes the zones, the key and the zones' update policy match, and
	// adopts whatever already exists.
	Ensure(ctx context.Context, t DNSTenant) error
	// Remove deletes the zones and the key. Absent objects are not an error.
	Remove(ctx context.Context, t DNSTenant) error
}

// Forward is one resolver forwarding entry: queries for Domain go to Server.
type Forward struct {
	Domain      string
	Server      string
	Description string
}

// Resolver is the core router's resolver, which delegates tenant zones.
type Resolver interface {
	Ensure(ctx context.Context, fwds []Forward) error
	Remove(ctx context.Context, domains []string) error
}

// StateTenant is a tenant's state-store user and the prefix it is confined to.
type StateTenant struct {
	User   string
	Secret string
	Bucket string
	Prefix string
}

// StateStore is the tenant state store (ADR-0007).
type StateStore interface {
	Ensure(ctx context.Context, t StateTenant) error
	Remove(ctx context.Context, user string) error
}

// Claim is an index the live fabric is using, and the zone using it.
type Claim struct {
	Index int
	Zone  string
}

// Fabric reports which indexes the tenant fabric already carries (ADR-0015 §3).
type Fabric interface {
	Claims(ctx context.Context) ([]Claim, error)
}

var (
	ErrNotFound    = errors.New("tenant not found")
	ErrExists      = errors.New("tenant already exists")
	ErrExhausted   = errors.New("no free tenant index")
	ErrFabricInUse = errors.New("the fabric still carries this tenant's zone")
)

// InvalidError is a request the API refuses to act on.
type InvalidError struct{ Reason string }

func (e *InvalidError) Error() string { return "invalid request: " + e.Reason }

func invalid(format string, args ...any) error {
	return &InvalidError{Reason: fmt.Sprintf(format, args...)}
}

// StepError is a backend step that failed. Its message names the step only;
// the underlying error can carry backend addresses and is for the log.
type StepError struct {
	Step string
	Err  error
}

func (e *StepError) Error() string { return fmt.Sprintf("backend step %q failed", e.Step) }
func (e *StepError) Unwrap() error { return e.Err }
