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
	StepNetwork  = "network"
)

// Secrets are what the API keeps for a tenant. The TSIG and state secrets are
// kept usable because the API has to re-ensure them after a backend rebuild;
// the API token is kept only as a hash.
type Secrets struct {
	TSIG         string
	State        string
	APITokenHash []byte
	// Unreadable is set when a stored secret could not be opened - which is what
	// a rebuilt or rotated Transit key leaves behind (ADR-0016 §6). It is not the
	// same as a secret being empty, and the difference is the whole point: a
	// tenant is told to supply its secrets again only when the API has some it
	// cannot read, never because it happens to hold none.
	Unreadable bool
}

// Step is the last recorded outcome of one backend step.
type Step struct {
	Name      string    `json:"name"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Workload is a tenant VM as the registry holds it.
type Workload struct {
	Tenant   string
	Name     string
	Ordinal  int
	VMID     int
	MAC      string
	Address  string // the bare address, e.g. 10.20.129.10
	Cores    int
	MemoryMB int
	DiskGB   int
	SSHKeys  []string
	Status   Status
	// Kind tells a workload's own record apart from a name the tenant added.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ExtraRecord is a name a tenant publishes beside its workloads' own names.
type ExtraRecord struct {
	Tenant    string
	Name      string
	Address   string
	CreatedAt time.Time
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

	// Workloads. CreateWorkload allocates the ordinal under the same lock that
	// allocates an index, so two creates cannot share one.
	CreateWorkload(ctx context.Context, w Workload) (Workload, error)
	GetWorkload(ctx context.Context, tenantName, name string) (Workload, error)
	ListWorkloads(ctx context.Context, tenantName string) ([]Workload, error)
	SetWorkloadStatus(ctx context.Context, tenantName, name string, status Status) error
	DeleteWorkload(ctx context.Context, tenantName, name string) error

	// Extra records (ADR-0015 §13).
	PutRecord(ctx context.Context, r ExtraRecord) error
	ListRecords(ctx context.Context, tenantName string) ([]ExtraRecord, error)
	DeleteRecord(ctx context.Context, tenantName, name string) error

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
	// EnsureRecords publishes A records in the tenant's zone and the matching
	// PTRs in its reverse zone (ADR-0015 §13).
	EnsureRecords(ctx context.Context, zone, reverseZone string, recs []DNSRecord) error
	// RemoveRecords deletes those names and their PTRs. Absent names are not an
	// error.
	RemoveRecords(ctx context.Context, zone, reverseZone string, recs []DNSRecord) error
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

// VNetSpec is one VNet of a tenant network: the bridge name workloads attach
// to, and its VXLAN tag.
type VNetSpec struct {
	ID  string
	Tag int
}

// NetworkSpec is a tenant's network on the fabric (ADR-0015 §11).
type NetworkSpec struct {
	Zone       string
	Controller string
	Node       string
	VRFVNI     int
	VNets      []VNetSpec
	Subnet     string
	Gateway    string
}

// Network builds a tenant's network on the fabric.
type Network interface {
	Ensure(ctx context.Context, n NetworkSpec) error
	Remove(ctx context.Context, n NetworkSpec) error
}

// WorkloadSpec is one VM as the hypervisor needs it (ADR-0015 §12). Everything
// here except the tenant's own choices is derived by the API.
type WorkloadSpec struct {
	Name           string
	Node           string
	VMID           int
	MAC            string
	Bridge         string
	Address        string // CIDR, e.g. 10.20.129.10/24
	Gateway        string
	Nameserver     string
	Cores          int
	MemoryMB       int
	DiskGB         int
	Disk           string // which disk to grow, e.g. scsi0
	Storage        string
	CIUser         string
	SSHKeys        []string
	Tags           []string
	TemplatePrefix string
}

// Compute builds a tenant's workloads.
type Compute interface {
	EnsureWorkload(ctx context.Context, w WorkloadSpec) error
	RemoveWorkload(ctx context.Context, node string, vmid int) error
}

// DNSRecord is one name a tenant publishes: a label in its own zone.
type DNSRecord struct {
	Name    string // label, e.g. "web" or "eds-1"
	Address string
	// Reverse is true for the name that owns the address: a workload's own.
	// A name a tenant adds beside it is an alias for the service, and several
	// may share one address, so only the workload publishes the PTR - otherwise
	// whichever name was written last would claim the reverse and the machine
	// would stop resolving back to itself.
	Reverse bool
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

// Enroller holds single-use enrollment tokens (ADR-0015 §10, ADR-0016 §4).
// OpenBao's response wrapping implements it.
type Enroller interface {
	// Wrap puts data behind a single-use token that lives for ttl.
	Wrap(ctx context.Context, data map[string]string, ttl time.Duration) (token string, expires time.Time, err error)
	// Unwrap spends the token and returns its data, or ErrNotRedeemable.
	Unwrap(ctx context.Context, token string) (map[string]string, error)
}

var (
	ErrNotFound    = errors.New("tenant not found")
	ErrExists      = errors.New("tenant already exists")
	ErrExhausted   = errors.New("no free tenant index")
	ErrFabricInUse = errors.New("the fabric still carries this tenant's zone")
	// ErrNotRedeemable is an enrollment token that was spent, expired, never
	// existed, or names another tenant. Which one is not said.
	ErrNotRedeemable = errors.New("enrollment token is not redeemable")
	// ErrNoEnrollment: the API runs without an Enroller, so only the operator
	// creates tenants.
	ErrNoEnrollment = errors.New("enrollment is not configured")
	// ErrHasWorkloads: a tenant with workloads is not deleted (ADR-0015 §2).
	ErrHasWorkloads = errors.New("the tenant still has workloads")
	// ErrWorkloadsExhausted: the tenant's workload ordinals are all taken.
	ErrWorkloadsExhausted = errors.New("no free workload ordinal")
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
