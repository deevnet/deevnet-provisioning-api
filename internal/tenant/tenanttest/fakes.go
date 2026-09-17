// Package tenanttest holds in-memory stand-ins for the registry and the backing
// services, so the tenant rules and the HTTP surface are tested without
// PostgreSQL, PowerDNS, the router, MinIO or Proxmox.
package tenanttest

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Store is an in-memory tenant.Store.
type Store struct {
	mu       sync.Mutex
	records  map[string]tenant.Record
	AuditLog []tenant.AuditEntry
}

func NewStore() *Store { return &Store{records: map[string]tenant.Record{}} }

func (s *Store) Get(_ context.Context, name string) (tenant.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[name]
	if !ok {
		return tenant.Record{}, tenant.ErrNotFound
	}
	r.Steps = append([]tenant.Step(nil), r.Steps...)
	return r, nil
}

func (s *Store) List(_ context.Context) ([]tenant.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]tenant.Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) Create(_ context.Context, name string, secrets tenant.Secrets, pick func(map[int]string) (int, error)) (tenant.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[name]; ok {
		return tenant.Record{}, tenant.ErrExists
	}
	held := map[int]string{}
	for _, r := range s.records {
		held[r.Index] = r.Name
	}
	n, err := pick(held)
	if err != nil {
		return tenant.Record{}, err
	}
	now := time.Now()
	r := tenant.Record{Name: name, Index: n, Status: tenant.StatusProvisioning, Secrets: secrets, CreatedAt: now, UpdatedAt: now}
	s.records[name] = r
	return r, nil
}

// Put registers a tenant directly, for tests that start from an existing registry.
func (s *Store) Put(r tenant.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.Name] = r
}

func (s *Store) SetStatus(_ context.Context, name string, status tenant.Status) error {
	return s.update(name, func(r *tenant.Record) { r.Status = status })
}

func (s *Store) SetSecrets(_ context.Context, name string, secrets tenant.Secrets) error {
	return s.update(name, func(r *tenant.Record) { r.Secrets = secrets })
}

func (s *Store) RecordStep(_ context.Context, name, step string, stepErr error) error {
	return s.update(name, func(r *tenant.Record) {
		st := tenant.Step{Name: step, OK: stepErr == nil, UpdatedAt: time.Now()}
		if stepErr != nil {
			st.Error = stepErr.Error()
		}
		for i := range r.Steps {
			if r.Steps[i].Name == step {
				r.Steps[i] = st
				return
			}
		}
		r.Steps = append(r.Steps, st)
	})
}

func (s *Store) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[name]; !ok {
		return tenant.ErrNotFound
	}
	delete(s.records, name)
	return nil
}

func (s *Store) Audit(_ context.Context, e tenant.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AuditLog = append(s.AuditLog, e)
	return nil
}

func (s *Store) update(name string, fn func(*tenant.Record)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[name]
	if !ok {
		return tenant.ErrNotFound
	}
	fn(&r)
	r.UpdatedAt = time.Now()
	s.records[name] = r
	return nil
}

// Backends records what the service asked of each backing service, and fails
// a step on demand.
type Backends struct {
	mu sync.Mutex

	DNSTenants   map[string]tenant.DNSTenant
	Forwards     map[string]tenant.Forward
	States       map[string]tenant.StateTenant
	FabricClaims []tenant.Claim

	FailDNS, FailResolver, FailState, FailFabric error
}

func NewBackends() *Backends {
	return &Backends{
		DNSTenants: map[string]tenant.DNSTenant{},
		Forwards:   map[string]tenant.Forward{},
		States:     map[string]tenant.StateTenant{},
	}
}

// DNS, Resolver, State and Fabric expose the same recorder behind each interface.
func (b *Backends) DNS() tenant.DNS           { return dnsFake{b} }
func (b *Backends) Resolver() tenant.Resolver { return resolverFake{b} }
func (b *Backends) State() tenant.StateStore  { return stateFake{b} }
func (b *Backends) Fabric() tenant.Fabric     { return fabricFake{b} }

type dnsFake struct{ b *Backends }

func (f dnsFake) Ensure(_ context.Context, t tenant.DNSTenant) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailDNS != nil {
		return f.b.FailDNS
	}
	f.b.DNSTenants[t.KeyName] = t
	return nil
}

func (f dnsFake) Remove(_ context.Context, t tenant.DNSTenant) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailDNS != nil {
		return f.b.FailDNS
	}
	delete(f.b.DNSTenants, t.KeyName)
	return nil
}

type resolverFake struct{ b *Backends }

func (f resolverFake) Ensure(_ context.Context, fwds []tenant.Forward) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailResolver != nil {
		return f.b.FailResolver
	}
	for _, fw := range fwds {
		f.b.Forwards[fw.Domain] = fw
	}
	return nil
}

func (f resolverFake) Remove(_ context.Context, domains []string) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailResolver != nil {
		return f.b.FailResolver
	}
	for _, d := range domains {
		delete(f.b.Forwards, d)
	}
	return nil
}

type stateFake struct{ b *Backends }

func (f stateFake) Ensure(_ context.Context, t tenant.StateTenant) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailState != nil {
		return f.b.FailState
	}
	f.b.States[t.User] = t
	return nil
}

func (f stateFake) Remove(_ context.Context, user string) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailState != nil {
		return f.b.FailState
	}
	delete(f.b.States, user)
	return nil
}

type fabricFake struct{ b *Backends }

func (f fabricFake) Claims(context.Context) ([]tenant.Claim, error) {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailFabric != nil {
		return nil, f.b.FailFabric
	}
	return append([]tenant.Claim(nil), f.b.FabricClaims...), nil
}

// MobileSite is the mobile site's constants, as the API is deployed there.
func MobileSite() tenant.Site {
	return tenant.Site{
		Name:              "mobile",
		Octet:             20,
		RootDomain:        "deevnet.net",
		VRFVNIBase:        10000,
		VNetVNIBase:       20000,
		ControllerID:      "evpn1",
		Node:              "dv02hyp002p02",
		DNSUpdateServer:   "tdns.mobile.deevnet.net",
		DNSApexNS:         "dv02idn001v01.mobile.deevnet.net",
		DNSUpdateFrom:     []string{"10.20.99.0/24", "10.20.10.0/24", "10.20.50.0/24"},
		StateEndpoint:     "http://tfstate.mobile.deevnet.net:9000",
		StateBucket:       "tf-state",
		ResolverForwardTo: "10.20.25.21",
	}
}

// TokenKey is the token MAC key the fakes use.
var TokenKey = []byte("0123456789abcdef0123456789abcdef-test-only")

// Enroller is an in-memory single-use token store.
type Enroller struct {
	mu     sync.Mutex
	tokens map[string]map[string]string
	next   int
}

func (e *Enroller) Wrap(_ context.Context, data map[string]string, ttl time.Duration) (string, time.Time, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tokens == nil {
		e.tokens = map[string]map[string]string{}
	}
	e.next++
	tok := "wrap-" + string(rune('a'+e.next%26)) + time.Now().Format("150405.000000000")
	e.tokens[tok] = data
	return tok, time.Now().Add(ttl), nil
}

func (e *Enroller) Unwrap(_ context.Context, token string) (map[string]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	data, ok := e.tokens[token]
	if !ok {
		return nil, tenant.ErrNotRedeemable
	}
	delete(e.tokens, token)
	return data, nil
}

// NewService wires a service to fresh fakes, with enrollment on.
func NewService() (*tenant.Service, *Store, *Backends) {
	st := NewStore()
	b := NewBackends()
	tokens, err := tenant.NewTokens(TokenKey)
	if err != nil {
		panic(err)
	}
	return &tenant.Service{
		Site:     MobileSite(),
		Store:    st,
		DNS:      b.DNS(),
		Resolver: b.Resolver(),
		State:    b.State(),
		Fabric:   b.Fabric(),
		Tokens:   tokens,
		Enroller: &Enroller{},
	}, st, b
}
