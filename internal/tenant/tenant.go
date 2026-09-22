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
	StepWiFiKey  = "wifi-key"
	StepBroker   = "broker-account"
	StepLogStore = "log-store"
)

// LogTenant is one tenant's users in the log store. The partitions are not in
// it: both ends derive them from the index, so a caller cannot name another
// tenant's partition (ADR-0027 §2).
type LogTenant struct {
	Name        string
	Index       int
	IngestToken string
	ReadToken   string
}

// LogWriter maintains a tenant's users in the log store.
//
// Like BrokerWriter, nil is legal: a site with no log store is a legitimate
// site, and the tenant then simply has no log tokens rather than failing to be
// created.
type LogWriter interface {
	Put(ctx context.Context, t LogTenant) error
	Remove(ctx context.Context, name string, index int) error
}

// Secrets are what the API keeps for a tenant. The TSIG and state secrets are
// kept usable because the API has to re-ensure them after a backend rebuild;
// the API token is kept only as a hash.
type Secrets struct {
	TSIG         string
	State        string
	APITokenHash []byte
	// LogIngest writes the tenant's own log partition; LogRead reads its three
	// (ADR-0027 §2). Both are kept usable, like TSIG and State and unlike the
	// API token, because the store is configured with the token itself: vmauth
	// compares what it was given, so a hash would be of no use to it. They are
	// sealed in the same column family and restored the same way.
	LogIngest string
	LogRead   string
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

// WiFiKey is a tenant's PPSK key for one trust class, as the registry holds it.
// One key serves every device that tenant flashes with it; the substrate does
// not know those devices individually (ADR-0012 §3, amended 2026-09-18).
type WiFiKey struct {
	Tenant     string
	Name       string
	TrustClass string
	// PSK is the credential itself. The tenant's own state holds the
	// authoritative copy (ADR-0012 §4); this one exists so the API can put the
	// key back after a controller rebuild without a visit to every device.
	PSK string
	// Unreadable: the stored PSK would not open, exactly as Secrets.Unreadable.
	// The tenant is told to supply it again; the key itself is not lost,
	// because the tenant has it.
	Unreadable bool
	Status     Status
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Device is one of a tenant's edge devices as the registry holds it
// (ADR-0012 §3). The entry is the device's identity: an application-owned
// device takes no substrate host record, leases from its trust class's pool and
// is named in its owner's own zone (ADR-0011 open question 3).
//
// A row here is identity, never authorization. What a device is allowed to
// consume is carried by a credential it proves (ADR-0020 §2), and that
// credential is a later layer - this type deliberately holds none.
type Device struct {
	Tenant     string
	Name       string
	TrustClass string
	// MAC is optional, and is a label for the owner's own inventory. Nothing
	// the substrate does may turn on it: a MAC is trivially spoofed on a shared
	// segment, so binding to one stops nobody who is trying (ADR-0012 §3) and
	// it is explicitly not an authorization input (ADR-0020 §2).
	MAC       string
	Status    Status
	CreatedAt time.Time
	UpdatedAt time.Time
}

// BrokerAccount is an MQTT account as the registry holds it (ADR-0012 §3).
//
// It belongs either to one of the tenant's devices or to a tenant workload:
// Device is optional, and empty means a workload account. A device account
// needs trust class iot, because the standard declares no
// iot_vendor -> iot_backend path and an account that could never be used
// would imply one.
type BrokerAccount struct {
	Tenant    string
	Name      string
	Device    string
	Publish   []string
	Subscribe []string

	// PasswordHash is a bcrypt hash and NOT a sealed secret, which is a
	// deliberate difference from WiFiKey.
	//
	// A Wi-Fi key is stored because the controller needs the plaintext, so the
	// API keeps a usable copy and seals it. The broker needs only the hash, so
	// the API never holds the plaintext at rest at all - the tenant's own
	// state is the only place it exists (ADR-0012 §4).
	//
	// It is not sealed, and that is the point rather than an omission. An
	// unreadable hash would leave the API unable to restore the account, and
	// the tenant's only recovery would be a new password and a visit to every
	// device holding the old one - which is exactly what ADR-0012 §5 says a
	// substrate rebuild must never cost. A bcrypt hash is already a one-way
	// function; sealing it would trade a guarantee for very little.
	PasswordHash string
	Status       Status
	CreatedAt    time.Time
	UpdatedAt    time.Time
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

	// Wi-Fi keys (ADR-0012 §3). Nothing is allocated, so no lock is needed.
	PutWiFiKey(ctx context.Context, k WiFiKey) (WiFiKey, error)
	GetWiFiKey(ctx context.Context, tenantName, name string) (WiFiKey, error)
	ListWiFiKeys(ctx context.Context, tenantName string) ([]WiFiKey, error)
	SetWiFiKeyStatus(ctx context.Context, tenantName, name string, status Status) error
	DeleteWiFiKey(ctx context.Context, tenantName, name string) error

	// Broker accounts (ADR-0012 §3). Nothing is allocated. The hash is stored
	// before the writer is called, so a retry after an ambiguous failure sends
	// the same one - see CreateBrokerAccount.
	PutBrokerAccount(ctx context.Context, a BrokerAccount) (BrokerAccount, error)
	GetBrokerAccount(ctx context.Context, tenantName, name string) (BrokerAccount, error)
	ListBrokerAccounts(ctx context.Context, tenantName string) ([]BrokerAccount, error)
	SetBrokerAccountStatus(ctx context.Context, tenantName, name string, status Status) error
	DeleteBrokerAccount(ctx context.Context, tenantName, name string) error

	// Devices (ADR-0012 §3). Nothing is allocated, so no lock is needed, and
	// nothing is sealed, because a device row carries no secret.
	PutDevice(ctx context.Context, d Device) (Device, error)
	GetDevice(ctx context.Context, tenantName, name string) (Device, error)
	ListDevices(ctx context.Context, tenantName string) ([]Device, error)
	DeleteDevice(ctx context.Context, tenantName, name string) error

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

// WiFiKeySpec is one PPSK key as the wireless controller needs it. The VLAN is
// the trust class's, never the tenant's choice, which is what keeps a tenant
// network off the air (ADR-0011 Option B stays rejected).
type WiFiKeySpec struct {
	// SSID whose PPSK profile holds the key. The profile is resolved from it.
	SSID string
	// Name of the key inside that profile: "<tenant>-<label>".
	Name string
	PSK  string
	VLAN int
}

// Wireless issues PPSK keys into the profiles inventory declares (ADR-0012 §6).
// The keys are the carve-out: inventory owns the SSID and the profile, this
// owns what is inside it.
type Wireless interface {
	// EnsureKey makes the named key exist with this PSK and VLAN, correcting one
	// that is already there.
	EnsureKey(ctx context.Context, k WiFiKeySpec) error
	// RemoveKey deletes it. A key that is not there is not an error.
	RemoveKey(ctx context.Context, ssid, name string) error
}

// BrokerWriter puts an account into the broker's auth database.
//
// The broker's database is not reachable from the network (CHG-0016), so this
// is not a database client: it is a request to a program on the messaging VM,
// which is the only thing that can reach it.
//
// Every operation is idempotent. The caller supplies the same hash on a retry,
// so an ambiguous failure - a timeout, a dropped connection - is safe to
// repeat rather than something that has to be reconciled.
type BrokerWriter interface {
	// Put creates or updates the account. Patterns arrive already carrying the
	// tenant's prefix; the far end re-checks that and refuses anything else.
	Put(ctx context.Context, a BrokerAccount) error
	// Remove deletes it. An account that is not there is not an error.
	Remove(ctx context.Context, tenantName, name string) error
}

// ValidPSK reports whether s is a password the wireless controller will take:
// 8 to 63 visible ASCII characters, its own documented rule. It is applied to
// supplied PSKs as well as generated ones, so a restore cannot smuggle in a
// value the controller will reject.
func ValidPSK(s string) bool {
	if len(s) < 8 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// NormalizeMAC canonicalises a MAC to lowercase colon-separated form and
// reports whether it was one at all. It accepts the three spellings hardware
// and vendor tooling actually print - aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF and
// aabbccddeeff - because a tenant copying an address off a label or a serial
// console should not have to reformat it.
//
// This validates shape, nothing more. A well-formed MAC is still not evidence
// of who is calling (ADR-0020 §2).
func NormalizeMAC(s string) (string, bool) {
	var hex []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':' || c == '-':
			continue
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			hex = append(hex, c)
		case c >= 'A' && c <= 'F':
			hex = append(hex, c+('a'-'A'))
		default:
			return "", false
		}
	}
	if len(hex) != 12 {
		return "", false
	}
	out := make([]byte, 0, 17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[i], hex[i+1])
	}
	return string(out), true
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
