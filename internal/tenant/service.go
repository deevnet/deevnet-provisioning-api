package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Outcome says what a create call did, so a caller can tell a fresh tenant from
// a restore that kept its index and one that was issued a new index.
type Outcome string

const (
	OutcomeCreated    Outcome = "created"
	OutcomeRestored   Outcome = "restored"
	OutcomeReissued   Outcome = "reissued"
	OutcomeResumed    Outcome = "resumed"
	OutcomeReconciled Outcome = "reconciled"
)

// CreateRequest creates a tenant, or restores one from what its state holds.
//
// A restore supplies the index and all three secrets. The index is kept when it
// is free and issued anew when another tenant holds it (ADR-0015 §5); the
// secrets are always kept, so the tenant's keys keep working.
type CreateRequest struct {
	Name        string
	Index       int
	TSIGSecret  string
	StateSecret string
	APIToken    string
}

func (r CreateRequest) suppliesSecrets() bool {
	return r.TSIGSecret != "" || r.StateSecret != "" || r.APIToken != ""
}

// Issued are the plaintext secrets a create call hands back. APIToken is empty
// when the call neither generated nor received one: the API only keeps its hash.
type Issued struct {
	// LogIngestToken and LogReadToken are the tenant's credentials for the log
	// store (ADR-0027). Unlike the API token they are readable afterwards, so
	// reconcile returns them too: that is how a tenant created before the store
	// existed gets hold of them without being rebuilt.
	LogIngestToken string
	LogReadToken   string
	TSIGSecret     string
	StateSecret    string
	APIToken       string
}

// Result is a tenant after a create, restore, resume or reconcile.
type Result struct {
	Record  Record
	Outcome Outcome
	Issued  Issued
}

// Service applies ADR-0015. Actor names the caller in the audit log; the first
// slice has one caller, the operator.
type Service struct {
	Site     Site
	Store    Store
	DNS      DNS
	Resolver Resolver
	State    StateStore
	Fabric   Fabric
	// Network and Compute build the tenant's network and workloads (ADR-0015
	// §11, §12).
	Network Network
	Compute Compute
	// Wireless issues tenant Wi-Fi keys (ADR-0012 §3). Nil at a site with no
	// wireless controller, where the Wi-Fi endpoints refuse rather than panic.
	Wireless Wireless

	// BrokerWriter puts MQTT accounts into the broker's auth database, through
	// the writer on the messaging VM (CHG-0016). Nil at a site with no broker,
	// which is a legitimate site and the state every site was in before
	// CHG-0015 - the routes then refuse with a reason rather than panicking.
	BrokerWriter BrokerWriter
	// LogWriter maintains each tenant's users in the log store (ADR-0027,
	// CHG-0020). Nil when the site has no store, and then a tenant simply
	// has no log tokens.
	LogWriter LogWriter
	// Tokens issues and verifies tenant API tokens. Required.
	Tokens *Tokens
	// Enroller backs admission. Nil means only the operator creates tenants.
	Enroller      Enroller
	EnrollmentTTL time.Duration
	Logger        *slog.Logger

	// sdn serialises SDN applies, which are cluster-wide.
	sdn sync.Mutex
}

// The audit log says who did it. The caller is put in the context by the
// server, because the service is reached the same way whoever is calling: a
// log that named the operator for everything would attribute a tenant's own
// workloads, names and restores to the operator.
type actorKey struct{}

// WithActor names the caller for anything audited under this context.
func WithActor(ctx context.Context, actor string) context.Context {
	if actor == "" {
		return ctx
	}
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorFrom(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey{}).(string); ok && a != "" {
		return a
	}
	// Nothing set it: a call that did not come through the server, such as a
	// test or a future scheduled task. Not the operator.
	return "unattributed"
}

// Create creates, restores or resumes a tenant.
func (s *Service) Create(ctx context.Context, req CreateRequest) (Result, error) {
	if err := validateCreate(req); err != nil {
		return Result{}, err
	}
	// A restore brings the token the API issued; one it did not issue, or
	// issued for another tenant, restores nothing.
	if req.APIToken != "" {
		if name, ok := s.Tokens.Verify(req.APIToken); !ok || name != req.Name {
			return Result{}, invalid("api_token was not issued for tenant %q", req.Name)
		}
	}

	rec, err := s.Store.Get(ctx, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		return s.createNew(ctx, req)
	case err != nil:
		return Result{}, err
	}

	switch rec.Status {
	case StatusReady:
		// A ready tenant is only touched by a caller that brings its secrets,
		// which is a restore over a registry that survived. Anything else is a
		// second create of the same name.
		if !req.suppliesAllSecrets() {
			return Result{}, ErrExists
		}
		return s.restoreExisting(ctx, rec, req, OutcomeReconciled)
	case StatusProvisioning:
		return s.restoreExisting(ctx, rec, req, OutcomeResumed)
	default:
		return Result{}, invalid("tenant %q is %s; finish deleting it first", rec.Name, rec.Status)
	}
}

func (r CreateRequest) suppliesAllSecrets() bool {
	return r.TSIGSecret != "" && r.StateSecret != "" && r.APIToken != ""
}

func validateCreate(req CreateRequest) error {
	if !ValidName(req.Name) {
		return invalid("name must be 1-8 lowercase alphanumerics starting with a letter")
	}
	if req.Index != 0 && (req.Index < MinIndex || req.Index > MaxAllocatable) {
		return invalid("index must be %d-%d", MinIndex, MaxAllocatable)
	}
	if req.suppliesSecrets() && !req.suppliesAllSecrets() {
		return invalid("a restore supplies all three secrets or none")
	}
	if req.TSIGSecret != "" {
		raw, err := base64.StdEncoding.DecodeString(req.TSIGSecret)
		if err != nil || len(raw) < 16 {
			return invalid("tsig_secret must be base64 of at least 16 bytes")
		}
	}
	// MinIO: "Secret key should be in between 8 and 40".
	if req.StateSecret != "" && (len(req.StateSecret) < 8 || len(req.StateSecret) > 40) {
		return invalid("state_secret must be 8-40 characters")
	}
	return nil
}

func (s *Service) createNew(ctx context.Context, req CreateRequest) (Result, error) {
	// The fabric is read before the lock is taken, so a slow Proxmox API never
	// holds up other creates. A zone created between the read and the insert
	// would have to come from a tenant with no registry row, which is exactly
	// what the read is there to catch on the next create.
	claims, err := s.Fabric.Claims(ctx)
	if err != nil {
		return Result{}, &StepError{Step: "fabric", Err: err}
	}

	issued, secrets, err := s.secretsFor(req)
	if err != nil {
		return Result{}, err
	}

	pick := func(held map[int]string) (int, error) {
		return pickIndex(req.Name, req.Index, held, claims)
	}
	rec, err := s.Store.Create(ctx, req.Name, secrets, pick)
	if err != nil {
		return Result{}, err
	}

	outcome := OutcomeCreated
	if req.Index != 0 {
		outcome = OutcomeRestored
		if rec.Index != req.Index {
			outcome = OutcomeReissued
		}
	}
	s.audit(ctx, "create", rec.Name, map[string]any{
		"index": rec.Index, "requested_index": req.Index, "outcome": string(outcome),
	})

	rec, err = s.ensure(ctx, rec)
	return Result{Record: rec, Outcome: outcome, Issued: issued}, err
}

// restoreExisting brings a registered tenant back into line. Supplied secrets
// win over stored ones, because the tenant's state is the authoritative copy
// (ADR-0015 §4). The registry's index wins over a supplied one: while the row
// exists, the registry is not the thing that was lost.
func (s *Service) restoreExisting(ctx context.Context, rec Record, req CreateRequest, outcome Outcome) (Result, error) {
	issued := Issued{TSIGSecret: rec.Secrets.TSIG, StateSecret: rec.Secrets.State}
	secrets := rec.Secrets

	if req.suppliesAllSecrets() {
		issued = Issued{TSIGSecret: req.TSIGSecret, StateSecret: req.StateSecret, APIToken: req.APIToken}
		secrets = Secrets{TSIG: req.TSIGSecret, State: req.StateSecret, APITokenHash: HashToken(req.APIToken)}
	} else {
		// Resuming without secrets means the caller never received the first
		// response, so the token it would need was never delivered. Issue a new
		// one; the old hash is unusable to anyone.
		tok, err := s.Tokens.Issue(rec.Name)
		if err != nil {
			return Result{}, err
		}
		issued.APIToken = tok
		secrets.APITokenHash = HashToken(tok)
	}

	if err := s.Store.SetSecrets(ctx, rec.Name, secrets); err != nil {
		return Result{}, err
	}
	rec.Secrets = secrets
	s.audit(ctx, string(outcome), rec.Name, map[string]any{"index": rec.Index, "requested_index": req.Index})

	rec, err := s.ensure(ctx, rec)
	return Result{Record: rec, Outcome: outcome, Issued: issued}, err
}

// Reconcile re-ensures every backend for a registered tenant with the secrets
// the registry holds: the repair after a backend is rebuilt.
func (s *Service) Reconcile(ctx context.Context, name string) (Result, error) {
	rec, err := s.Store.Get(ctx, name)
	if err != nil {
		return Result{}, err
	}
	if rec.Status == StatusDeleting {
		return Result{}, invalid("tenant %q is deleting; finish deleting it first", name)
	}
	s.audit(ctx, "reconcile", name, map[string]any{"index": rec.Index})
	rec, err = s.ensure(ctx, rec)
	return Result{
		Record:  rec,
		Outcome: OutcomeReconciled,
		// The log tokens ride along: they are readable, and a reconcile is how a
		// tenant created before the store existed is handed them.
		Issued: Issued{TSIGSecret: rec.Secrets.TSIG, StateSecret: rec.Secrets.State,
			LogIngestToken: rec.Secrets.LogIngest, LogReadToken: rec.Secrets.LogRead},
	}, err
}

// Get returns a registered tenant.
func (s *Service) Get(ctx context.Context, name string) (Record, error) {
	if !ValidName(name) {
		return Record{}, ErrNotFound
	}
	return s.Store.Get(ctx, name)
}

// List returns every registered tenant, by index.
func (s *Service) List(ctx context.Context) ([]Record, error) {
	recs, err := s.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Index < recs[j].Index })
	return recs, nil
}

// Delete removes a tenant's substrate objects and its registry row. It refuses
// while the fabric still carries the tenant's zone: the tenant destroys its own
// resources first (ADR-0015 §2).
func (s *Service) Delete(ctx context.Context, name string) error {
	rec, err := s.Get(ctx, name)
	if err != nil {
		return err
	}

	// The tenant's own workloads are destroyed first: the API will not remove a
	// network under a running VM (ADR-0015 §2).
	workloads, err := s.Store.ListWorkloads(ctx, name)
	if err != nil {
		return err
	}
	if len(workloads) > 0 {
		return ErrHasWorkloads
	}
	// A zone on the fabric that the API did not build is also in the way.
	claims, err := s.Fabric.Claims(ctx)
	if err != nil {
		return &StepError{Step: "fabric", Err: err}
	}
	for _, c := range claims {
		if c.Zone == name && s.Network == nil {
			return ErrFabricInUse
		}
	}

	if err := s.Store.SetStatus(ctx, name, StatusDeleting); err != nil {
		return err
	}
	s.audit(ctx, "delete", name, map[string]any{"index": rec.Index})

	// A tenant's Wi-Fi keys go with it. They are credentials rather than
	// resources, so unlike workloads they do not block the delete - but they do
	// have to be revoked, because the registry row is about to disappear and a
	// key left in the controller's profile would then belong to nobody and
	// still let a device onto the IoT segment.
	wifiKeys, err := s.Store.ListWiFiKeys(ctx, name)
	if err != nil {
		return err
	}

	// Reverse of create: stop resolving the zones before they disappear.
	steps := []struct {
		name string
		run  func() error
	}{
		{StepWiFiKey, func() error {
			for _, k := range wifiKeys {
				if err := s.removeKeyFromController(ctx, k); err != nil {
					return err
				}
			}
			return nil
		}},
		{StepNetwork, func() error { return s.removeNetwork(ctx, rec) }},
		{StepResolver, func() error { return s.Resolver.Remove(ctx, s.zones(rec)) }},
		{StepDNS, func() error { return s.DNS.Remove(ctx, s.dnsTenant(rec)) }},
		{StepState, func() error { return s.State.Remove(ctx, rec.Name) }},
	}
	if s.LogWriter != nil {
		steps = append([]struct {
			name string
			run  func() error
		}{{StepLogStore, func() error { return s.removeLogTokens(ctx, rec) }}}, steps...)
	}

	for _, st := range steps {
		if err := st.run(); err != nil {
			s.recordStep(ctx, name, st.name, err)
			return &StepError{Step: st.name, Err: err}
		}
	}
	return s.Store.Delete(ctx, name)
}

// network builds the tenant's fabric objects. SDN apply is cluster-wide, so
// this is serialised across tenants (ADR-0015 §11).
func (s *Service) network(ctx context.Context, rec Record) error {
	if s.Network == nil {
		return nil
	}
	s.sdn.Lock()
	defer s.sdn.Unlock()
	return s.Network.Ensure(ctx, s.Site.Network(rec.Name, rec.Index))
}

func (s *Service) removeNetwork(ctx context.Context, rec Record) error {
	if s.Network == nil {
		return nil
	}
	s.sdn.Lock()
	defer s.sdn.Unlock()
	return s.Network.Remove(ctx, s.Site.Network(rec.Name, rec.Index))
}

// --- Workloads (ADR-0015 §12) ------------------------------------------------

// WorkloadRequest is what a tenant declares. Everything else is derived.
type WorkloadRequest struct {
	Name     string
	Cores    int
	MemoryMB int
	DiskGB   int
	SSHKeys  []string
}

// CreateWorkload builds a VM in the tenant's network and publishes its name.
// Calling it again for the same name re-applies, so a restore converges.
func (s *Service) CreateWorkload(ctx context.Context, tenantName string, req WorkloadRequest) (Workload, error) {
	if s.Compute == nil {
		return Workload{}, invalid("this API builds no workloads")
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return Workload{}, err
	}
	if rec.Status != StatusReady {
		return Workload{}, invalid("tenant %q is %s", tenantName, rec.Status)
	}
	if !ValidWorkloadName(req.Name) {
		return Workload{}, invalid("workload name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if req.Cores < 0 || req.MemoryMB < 0 || req.DiskGB < 0 {
		return Workload{}, invalid("cores, memory and disk cannot be negative")
	}

	w, err := s.Store.GetWorkload(ctx, tenantName, req.Name)
	switch {
	case errors.Is(err, ErrNotFound):
		w = Workload{
			Tenant:   tenantName,
			Name:     req.Name,
			Cores:    orDefaultInt(req.Cores, 2),
			MemoryMB: orDefaultInt(req.MemoryMB, 2048),
			DiskGB:   req.DiskGB,
			SSHKeys:  req.SSHKeys,
			Status:   StatusProvisioning,
		}
		// The store allocates the ordinal; the rest derives from it.
		if w, err = s.Store.CreateWorkload(ctx, w); err != nil {
			return Workload{}, err
		}
		s.audit(ctx, "workload-create", tenantName, map[string]any{"workload": w.Name, "ordinal": w.Ordinal, "vmid": w.VMID})
	case err != nil:
		return Workload{}, err
	default:
		// Re-applying an existing workload keeps its identity and takes the
		// new sizing.
		w.Cores = orDefaultInt(req.Cores, w.Cores)
		w.MemoryMB = orDefaultInt(req.MemoryMB, w.MemoryMB)
		if req.DiskGB > 0 {
			w.DiskGB = req.DiskGB
		}
		if len(req.SSHKeys) > 0 {
			w.SSHKeys = req.SSHKeys
		}
		if _, err := s.Store.CreateWorkload(ctx, w); err != nil {
			return Workload{}, err
		}
	}

	if err := s.Compute.EnsureWorkload(ctx, s.workloadSpec(rec, w)); err != nil {
		s.logger().Error("building workload", "tenant", tenantName, "workload", w.Name, "err", err)
		return w, &StepError{Step: "workload", Err: err}
	}
	// The API publishes a workload's own name (ADR-0015 §13).
	if err := s.DNS.EnsureRecords(ctx, s.Site.Zone(tenantName), s.Site.Numbering(rec.Index).ReverseZone,
		[]DNSRecord{{Name: w.Name, Address: w.Address, Reverse: true}}); err != nil {
		s.logger().Error("publishing workload", "tenant", tenantName, "workload", w.Name, "err", err)
		return w, &StepError{Step: StepDNS, Err: err}
	}
	if err := s.Store.SetWorkloadStatus(ctx, tenantName, w.Name, StatusReady); err != nil {
		return w, err
	}
	w.Status = StatusReady
	return w, nil
}

// GetWorkload returns one workload.
func (s *Service) GetWorkload(ctx context.Context, tenantName, name string) (Workload, error) {
	return s.Store.GetWorkload(ctx, tenantName, name)
}

// ListWorkloads returns a tenant's workloads, by ordinal.
func (s *Service) ListWorkloads(ctx context.Context, tenantName string) ([]Workload, error) {
	ws, err := s.Store.ListWorkloads(ctx, tenantName)
	if err != nil {
		return nil, err
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].Ordinal < ws[j].Ordinal })
	return ws, nil
}

// DeleteWorkload removes the VM and its published name.
func (s *Service) DeleteWorkload(ctx context.Context, tenantName, name string) error {
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return err
	}
	w, err := s.Store.GetWorkload(ctx, tenantName, name)
	if err != nil {
		return err
	}
	if s.Compute != nil {
		if err := s.Compute.RemoveWorkload(ctx, s.Site.Node, w.VMID); err != nil {
			return &StepError{Step: "workload", Err: err}
		}
	}
	if err := s.DNS.RemoveRecords(ctx, s.Site.Zone(tenantName), s.Site.Numbering(rec.Index).ReverseZone,
		[]DNSRecord{{Name: w.Name, Address: w.Address, Reverse: true}}); err != nil {
		return &StepError{Step: StepDNS, Err: err}
	}
	s.audit(ctx, "workload-delete", tenantName, map[string]any{"workload": name, "vmid": w.VMID})
	return s.Store.DeleteWorkload(ctx, tenantName, name)
}

func (s *Service) workloadSpec(rec Record, w Workload) WorkloadSpec {
	net := s.Site.Network(rec.Name, rec.Index)
	n := s.Site.Numbering(rec.Index)
	return WorkloadSpec{
		Name:           rec.Name + "-" + w.Name,
		Node:           s.Site.Node,
		VMID:           w.VMID,
		MAC:            w.MAC,
		Bridge:         net.VNets[0].ID,
		Address:        w.Address + "/24",
		Gateway:        n.Gateway,
		Nameserver:     s.Site.WorkloadResolver,
		Cores:          w.Cores,
		MemoryMB:       w.MemoryMB,
		DiskGB:         w.DiskGB,
		Disk:           s.Site.Disk,
		Storage:        s.Site.Storage,
		CIUser:         s.Site.CIUser,
		SSHKeys:        w.SSHKeys,
		Tags:           []string{"tenant", rec.Name},
		TemplatePrefix: s.Site.TemplatePrefix,
	}
}

// --- Extra records (ADR-0015 §13) --------------------------------------------

// PutRecord publishes a name in the tenant's zone, beside its workloads'.
func (s *Service) PutRecord(ctx context.Context, tenantName, name, address string) error {
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return err
	}
	if !ValidWorkloadName(name) {
		return invalid("record name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if !s.inTenantSubnet(rec, address) {
		return invalid("address %s is not in the tenant's subnet %s", address, s.Site.Numbering(rec.Index).Subnet)
	}
	if err := s.DNS.EnsureRecords(ctx, s.Site.Zone(tenantName), s.Site.Numbering(rec.Index).ReverseZone,
		[]DNSRecord{{Name: name, Address: address}}); err != nil {
		return &StepError{Step: StepDNS, Err: err}
	}
	if err := s.Store.PutRecord(ctx, ExtraRecord{Tenant: tenantName, Name: name, Address: address}); err != nil {
		return err
	}
	s.audit(ctx, "record-put", tenantName, map[string]any{"record": name, "address": address})
	return nil
}

// ListRecords returns the names a tenant added beside its workloads'.
func (s *Service) ListRecords(ctx context.Context, tenantName string) ([]ExtraRecord, error) {
	return s.Store.ListRecords(ctx, tenantName)
}

// DeleteRecord removes one of those names.
func (s *Service) DeleteRecord(ctx context.Context, tenantName, name string) error {
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return err
	}
	recs, err := s.Store.ListRecords(ctx, tenantName)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Name != name {
			continue
		}
		if err := s.DNS.RemoveRecords(ctx, s.Site.Zone(tenantName), s.Site.Numbering(rec.Index).ReverseZone,
			[]DNSRecord{{Name: r.Name, Address: r.Address}}); err != nil {
			return &StepError{Step: StepDNS, Err: err}
		}
		if err := s.Store.DeleteRecord(ctx, tenantName, name); err != nil {
			return err
		}
		s.audit(ctx, "record-delete", tenantName, map[string]any{"record": name})
		return nil
	}
	return ErrNotFound
}

// inTenantSubnet keeps a tenant from publishing a name pointing anywhere but
// its own subnet.
func (s *Service) inTenantSubnet(rec Record, address string) bool {
	prefix := fmt.Sprintf("10.%d.%d.", s.Site.Octet, 128+rec.Index)
	return strings.HasPrefix(address, prefix) && net.ParseIP(address) != nil
}

func orDefaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// EgressVRF is one tenant VRF the exit node gives a default route (ADR-0015 §7).
type EgressVRF struct {
	Tenant string `json:"tenant"`
	VRF    string `json:"vrf"`
}

// Egress lists the VRFs of every ready tenant, for the exit node's agent.
func (s *Service) Egress(ctx context.Context) ([]EgressVRF, error) {
	recs, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EgressVRF, 0, len(recs))
	for _, r := range recs {
		if r.Status == StatusReady {
			out = append(out, EgressVRF{Tenant: r.Name, VRF: egressVRFPrefix + r.Name})
		}
	}
	return out, nil
}

// ensure runs every backend step in order and records each outcome. It stops at
// the first failure, leaving the tenant provisioning so a second call resumes.
func (s *Service) ensure(ctx context.Context, rec Record) (Record, error) {
	steps := []struct {
		name string
		run  func() error
	}{
		// DNS first, then the delegation that points at it, so the resolver never
		// forwards a zone the server does not hold yet.
		{StepDNS, func() error { return s.DNS.Ensure(ctx, s.dnsTenant(rec)) }},
		{StepResolver, func() error { return s.Resolver.Ensure(ctx, s.forwards(rec)) }},
		{StepState, func() error { return s.State.Ensure(ctx, s.stateTenant(rec)) }},
		// Last, because it is the only step that changes the fabric, and the
		// tenant's own resources depend on it rather than the other way round.
		{StepNetwork, func() error { return s.network(ctx, rec) }},
	}
	// The tenant's users in the log store (ADR-0027, CHG-0020), before the
	// fabric step for the same reason as the others: the tenant's own
	// resources are the last thing built. Added only when the site has a
	// store, so a site without one records no step rather than a step that
	// did nothing.
	if s.LogWriter != nil {
		steps = append(steps, struct {
			name string
			run  func() error
		}{StepLogStore, func() error { return s.ensureLogTokens(ctx, rec) }})
	}

	for _, st := range steps {
		err := st.run()
		s.recordStep(ctx, rec.Name, st.name, err)
		if err != nil {
			if serr := s.Store.SetStatus(ctx, rec.Name, StatusProvisioning); serr != nil {
				s.logger().Error("recording status", "tenant", rec.Name, "err", serr)
			}
			return s.reload(ctx, rec), &StepError{Step: st.name, Err: err}
		}
	}
	if err := s.Store.SetStatus(ctx, rec.Name, StatusReady); err != nil {
		return rec, err
	}
	return s.reload(ctx, rec), nil
}

func (s *Service) reload(ctx context.Context, rec Record) Record {
	fresh, err := s.Store.Get(ctx, rec.Name)
	if err != nil {
		s.logger().Error("reloading tenant", "tenant", rec.Name, "err", err)
		return rec
	}
	return fresh
}

func (s *Service) recordStep(ctx context.Context, name, step string, stepErr error) {
	if stepErr != nil {
		s.logger().Error("backend step failed", "tenant", name, "step", step, "err", stepErr)
	}
	if err := s.Store.RecordStep(ctx, name, step, stepErr); err != nil {
		s.logger().Error("recording step", "tenant", name, "step", step, "err", err)
	}
}

func (s *Service) audit(ctx context.Context, action, name string, detail map[string]any) {
	if err := s.Store.Audit(ctx, AuditEntry{Actor: actorFrom(ctx), Action: action, Tenant: name, Detail: detail}); err != nil {
		s.logger().Error("writing audit log", "tenant", name, "action", action, "err", err)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

func (s *Service) zones(rec Record) []string {
	return []string{s.Site.Zone(rec.Name), s.Site.Numbering(rec.Index).ReverseZone}
}

func (s *Service) dnsTenant(rec Record) DNSTenant {
	return DNSTenant{
		KeyName:    rec.Name,
		Algorithm:  tsigAlgorithm,
		Secret:     rec.Secrets.TSIG,
		Zones:      s.zones(rec),
		ApexNS:     s.Site.DNSApexNS,
		UpdateFrom: s.Site.DNSUpdateFrom,
	}
}

func (s *Service) forwards(rec Record) []Forward {
	zones := s.zones(rec)
	return []Forward{
		{Domain: zones[0], Server: s.Site.ResolverForwardTo, Description: fmt.Sprintf("Deevnet API - tenant %s (ADR-0015)", rec.Name)},
		{Domain: zones[1], Server: s.Site.ResolverForwardTo, Description: fmt.Sprintf("Deevnet API - tenant %s reverse (ADR-0015)", rec.Name)},
	}
}

func (s *Service) stateTenant(rec Record) StateTenant {
	return StateTenant{
		User:   rec.Name,
		Secret: rec.Secrets.State,
		Bucket: s.Site.StateBucket,
		Prefix: s.Site.statePrefix(rec.Name),
	}
}

// pickIndex is ADR-0015 §3 and §5. held is what the registry holds; claims is
// what the live fabric carries.
func pickIndex(name string, requested int, held map[int]string, claims []Claim) (int, error) {
	fabric := map[int][]string{}
	for _, c := range claims {
		fabric[c.Index] = append(fabric[c.Index], c.Zone)
	}

	free := func(n int) bool {
		if _, taken := held[n]; taken {
			return false
		}
		// The tenant's own zone holding the index is the tenant coming back,
		// not a collision.
		for _, zone := range fabric[n] {
			if zone != name {
				return false
			}
		}
		return true
	}

	if requested != 0 && free(requested) {
		return requested, nil
	}

	// No usable request, but the fabric still carries a zone by this name: the
	// registry was lost and the tenant is being created again without its state.
	// Give it back the index its resources already use.
	var own []int
	for n, zones := range fabric {
		for _, z := range zones {
			if z == name {
				own = append(own, n)
			}
		}
	}
	sort.Ints(own)
	for _, n := range own {
		if n >= MinIndex && n <= MaxAllocatable && free(n) {
			return n, nil
		}
	}

	for n := MinIndex; n <= MaxAllocatable; n++ {
		if free(n) {
			return n, nil
		}
	}
	return 0, ErrExhausted
}

func (s *Service) secretsFor(req CreateRequest) (Issued, Secrets, error) {
	// The log tokens are minted here whichever branch runs. They are not part
	// of the restore contract: a tenant restoring itself supplies the three
	// secrets the API cannot re-derive, and a log token is not one of those -
	// the store is told what the token is, so issuing a fresh pair and writing
	// it to the store is always correct and never loses anything.
	logIngest, logRead, err := logTokens()
	if err != nil {
		return Issued{}, Secrets{}, err
	}
	if req.suppliesAllSecrets() {
		return Issued{TSIGSecret: req.TSIGSecret, StateSecret: req.StateSecret, APIToken: req.APIToken,
				LogIngestToken: logIngest, LogReadToken: logRead},
			Secrets{TSIG: req.TSIGSecret, State: req.StateSecret, APITokenHash: HashToken(req.APIToken),
				LogIngest: logIngest, LogRead: logRead},
			nil
	}
	tsigRaw := make([]byte, 32)
	if _, err := rand.Read(tsigRaw); err != nil {
		return Issued{}, Secrets{}, err
	}
	// 20 random bytes in hex is 40 characters: MinIO's upper limit, and no
	// characters a shell or a URL would mangle.
	state, err := randomHex(20)
	if err != nil {
		return Issued{}, Secrets{}, err
	}
	token, err := s.Tokens.Issue(req.Name)
	if err != nil {
		return Issued{}, Secrets{}, err
	}
	tsig := base64.StdEncoding.EncodeToString(tsigRaw)
	return Issued{TSIGSecret: tsig, StateSecret: state, APIToken: token,
			LogIngestToken: logIngest, LogReadToken: logRead},
		Secrets{TSIG: tsig, State: state, APITokenHash: HashToken(token),
			LogIngest: logIngest, LogRead: logRead},
		nil
}

// logTokens mints a tenant's pair. 32 bytes in hex is 64 characters: opaque,
// and made only of characters that cannot end a YAML scalar early, which is
// what the store's configuration file is.
func logTokens() (ingest, read string, err error) {
	if ingest, err = randomHex(32); err != nil {
		return "", "", err
	}
	if read, err = randomHex(32); err != nil {
		return "", "", err
	}
	return ingest, read, nil
}

// Admission is an admitted tenant name and the single-use token that creates it.
type Admission struct {
	Name            string
	EnrollmentToken string
	ExpiresAt       time.Time
}

// Admit lets a tenant create itself: it wraps the name behind a single-use
// enrollment token (ADR-0015 §10). A registered name is refused.
func (s *Service) Admit(ctx context.Context, name string) (Admission, error) {
	if s.Enroller == nil {
		return Admission{}, ErrNoEnrollment
	}
	if !ValidName(name) {
		return Admission{}, invalid("name must be 1-8 lowercase alphanumerics starting with a letter")
	}
	if _, err := s.Store.Get(ctx, name); err == nil {
		return Admission{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return Admission{}, err
	}
	ttl := s.EnrollmentTTL
	if ttl <= 0 {
		ttl = 72 * time.Hour
	}
	tok, expires, err := s.Enroller.Wrap(ctx, map[string]string{"tenant": name}, ttl)
	if err != nil {
		return Admission{}, &StepError{Step: "enrollment", Err: err}
	}
	s.audit(ctx, "admit", name, map[string]any{"expires_at": expires.UTC().Format(time.RFC3339)})
	return Admission{Name: name, EnrollmentToken: tok, ExpiresAt: expires}, nil
}

// Redeem spends an enrollment token for the tenant it was issued for. It is
// spent even when it names another tenant, so a guessed pairing costs the
// holder the token.
func (s *Service) Redeem(ctx context.Context, token, name string) error {
	if s.Enroller == nil {
		return ErrNoEnrollment
	}
	data, err := s.Enroller.Unwrap(ctx, token)
	if errors.Is(err, ErrNotRedeemable) {
		return ErrNotRedeemable
	}
	if err != nil {
		return &StepError{Step: "enrollment", Err: err}
	}
	if data["tenant"] != name {
		s.audit(ctx, "enrollment-mismatch", name, map[string]any{"token_for": data["tenant"]})
		return ErrNotRedeemable
	}
	s.audit(ctx, "enroll", name, nil)
	return nil
}

// Caller is who a tenant token speaks for.
type Caller struct {
	Tenant string
	// Registered is false when the token verifies but its tenant is not in the
	// registry: a tenant restoring itself after the registry was lost. Such a
	// caller may only create its own name.
	Registered bool
}

// Authenticate returns the tenant a bearer token speaks for. A registered
// tenant is accepted only with the token whose hash the registry holds, so a
// replaced token is revoked.
func (s *Service) Authenticate(ctx context.Context, token string) (Caller, bool) {
	if s.Tokens == nil {
		return Caller{}, false
	}
	name, ok := s.Tokens.Verify(token)
	if !ok {
		return Caller{}, false
	}
	rec, err := s.Store.Get(ctx, name)
	switch {
	case errors.Is(err, ErrNotFound):
		return Caller{Tenant: name}, true
	case err != nil:
		s.logger().Error("authenticating tenant token", "tenant", name, "err", err)
		return Caller{}, false
	}
	if subtleEqual(rec.Secrets.APITokenHash, HashToken(token)) {
		return Caller{Tenant: name, Registered: true}, true
	}
	return Caller{}, false
}

// HashToken is how a tenant API token is stored.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func subtleEqual(a, b []byte) bool {
	return len(a) == len(b) && hmacEqual(a, b)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
