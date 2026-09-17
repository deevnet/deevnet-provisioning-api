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
	"sort"
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
	TSIGSecret  string
	StateSecret string
	APIToken    string
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
	Logger   *slog.Logger
}

const operator = "operator"

// Create creates, restores or resumes a tenant.
func (s *Service) Create(ctx context.Context, req CreateRequest) (Result, error) {
	if err := validateCreate(req); err != nil {
		return Result{}, err
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
	if req.APIToken != "" && len(req.APIToken) < 32 {
		return invalid("api_token must be at least 32 characters")
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
		tok, err := randomHex(32)
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
		Issued:  Issued{TSIGSecret: rec.Secrets.TSIG, StateSecret: rec.Secrets.State},
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

	claims, err := s.Fabric.Claims(ctx)
	if err != nil {
		return &StepError{Step: "fabric", Err: err}
	}
	for _, c := range claims {
		if c.Zone == name {
			return ErrFabricInUse
		}
	}

	if err := s.Store.SetStatus(ctx, name, StatusDeleting); err != nil {
		return err
	}
	s.audit(ctx, "delete", name, map[string]any{"index": rec.Index})

	// Reverse of create: stop resolving the zones before they disappear.
	steps := []struct {
		name string
		run  func() error
	}{
		{StepResolver, func() error { return s.Resolver.Remove(ctx, s.zones(rec)) }},
		{StepDNS, func() error { return s.DNS.Remove(ctx, s.dnsTenant(rec)) }},
		{StepState, func() error { return s.State.Remove(ctx, rec.Name) }},
	}
	for _, st := range steps {
		if err := st.run(); err != nil {
			s.recordStep(ctx, name, st.name, err)
			return &StepError{Step: st.name, Err: err}
		}
	}
	return s.Store.Delete(ctx, name)
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
	if err := s.Store.Audit(ctx, AuditEntry{Actor: operator, Action: action, Tenant: name, Detail: detail}); err != nil {
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
	if req.suppliesAllSecrets() {
		return Issued{TSIGSecret: req.TSIGSecret, StateSecret: req.StateSecret, APIToken: req.APIToken},
			Secrets{TSIG: req.TSIGSecret, State: req.StateSecret, APITokenHash: HashToken(req.APIToken)},
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
	token, err := randomHex(32)
	if err != nil {
		return Issued{}, Secrets{}, err
	}
	tsig := base64.StdEncoding.EncodeToString(tsigRaw)
	return Issued{TSIGSecret: tsig, StateSecret: state, APIToken: token},
		Secrets{TSIG: tsig, State: state, APITokenHash: HashToken(token)},
		nil
}

// HashToken is how a tenant API token is stored.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
