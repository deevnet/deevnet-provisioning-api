// Package tenanttest holds in-memory stand-ins for the registry and the backing
// services, so the tenant rules and the HTTP surface are tested without
// PostgreSQL, PowerDNS, the router, MinIO or Proxmox.
package tenanttest

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Store is an in-memory tenant.Store.
type Store struct {
	// Unreadable: see Get.
	Unreadable   bool
	mu           sync.Mutex
	records      map[string]tenant.Record
	workloads    map[string]tenant.Workload
	wifiKeys     map[string]tenant.WiFiKey
	devices      map[string]tenant.Device
	brokerAccts  map[string]tenant.BrokerAccount
	extraRecords map[string]tenant.ExtraRecord
	AuditLog     []tenant.AuditEntry
}

func NewStore() *Store { return &Store{records: map[string]tenant.Record{}} }

// Unreadable makes every record report secrets the store cannot open, which is
// what a rebuilt or rotated Transit key looks like from above.
func (s *Store) Get(_ context.Context, name string) (tenant.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[name]
	if !ok {
		return tenant.Record{}, tenant.ErrNotFound
	}
	r.Steps = append([]tenant.Step(nil), r.Steps...)
	if s.Unreadable {
		r.Secrets.TSIG, r.Secrets.State, r.Secrets.Unreadable = "", "", true
	}
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

func (s *Store) SetDashboardOrg(_ context.Context, name string, orgID int) error {
	return s.update(name, func(r *tenant.Record) { r.DashboardOrg = orgID })
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

// --- Workloads and records ---------------------------------------------------

func (s *Store) CreateWorkload(_ context.Context, w tenant.Workload) (tenant.Workload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.workloads == nil {
		s.workloads = map[string]tenant.Workload{}
	}
	key := w.Tenant + "/" + w.Name
	if old, ok := s.workloads[key]; ok {
		w.Ordinal, w.VMID, w.MAC, w.Address = old.Ordinal, old.VMID, old.MAC, old.Address
		w.Status, w.CreatedAt = old.Status, old.CreatedAt
		s.workloads[key] = w
		return w, nil
	}
	taken := map[int]bool{}
	for _, x := range s.workloads {
		if x.Tenant == w.Tenant {
			taken[x.Ordinal] = true
		}
	}
	rec := s.records[w.Tenant]
	for n := 0; n < tenant.MaxWorkloads; n++ {
		if taken[n] {
			continue
		}
		site := MobileSite()
		w.Ordinal = n
		w.VMID = site.WorkloadVMID(rec.Index, n)
		w.MAC = site.MAC(w.VMID)
		w.Address = site.WorkloadAddress(rec.Index, n)
		w.CreatedAt = time.Now()
		s.workloads[key] = w
		return w, nil
	}
	return tenant.Workload{}, tenant.ErrWorkloadsExhausted
}

func (s *Store) GetWorkload(_ context.Context, tenantName, name string) (tenant.Workload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workloads[tenantName+"/"+name]
	if !ok {
		return tenant.Workload{}, tenant.ErrNotFound
	}
	return w, nil
}

func (s *Store) ListWorkloads(_ context.Context, tenantName string) ([]tenant.Workload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.Workload
	for _, w := range s.workloads {
		if w.Tenant == tenantName {
			out = append(out, w)
		}
	}
	return out, nil
}

func (s *Store) SetWorkloadStatus(_ context.Context, tenantName, name string, status tenant.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workloads[tenantName+"/"+name]
	if !ok {
		return tenant.ErrNotFound
	}
	w.Status = status
	s.workloads[tenantName+"/"+name] = w
	return nil
}

func (s *Store) DeleteWorkload(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workloads[tenantName+"/"+name]; !ok {
		return tenant.ErrNotFound
	}
	delete(s.workloads, tenantName+"/"+name)
	return nil
}

func (s *Store) PutWiFiKey(_ context.Context, k tenant.WiFiKey) (tenant.WiFiKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[k.Tenant]; !ok {
		return tenant.WiFiKey{}, tenant.ErrNotFound
	}
	if s.wifiKeys == nil {
		s.wifiKeys = map[string]tenant.WiFiKey{}
	}
	key := k.Tenant + "/" + k.Name
	if old, ok := s.wifiKeys[key]; ok {
		k.CreatedAt = old.CreatedAt
		// The trust class is fixed once issued; the service refuses a change
		// before it reaches the store, and the store does not silently take one.
		k.TrustClass = old.TrustClass
	} else {
		k.CreatedAt = time.Now()
	}
	k.UpdatedAt = time.Now()
	s.wifiKeys[key] = k
	return k, nil
}

func (s *Store) GetWiFiKey(_ context.Context, tenantName, name string) (tenant.WiFiKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.wifiKeys[tenantName+"/"+name]
	if !ok {
		return tenant.WiFiKey{}, tenant.ErrNotFound
	}
	if s.Unreadable {
		k.PSK, k.Unreadable = "", true
	}
	return k, nil
}

func (s *Store) ListWiFiKeys(_ context.Context, tenantName string) ([]tenant.WiFiKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.WiFiKey
	for _, k := range s.wifiKeys {
		if k.Tenant == tenantName {
			if s.Unreadable {
				k.PSK, k.Unreadable = "", true
			}
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetWiFiKeyStatus(_ context.Context, tenantName, name string, status tenant.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.wifiKeys[tenantName+"/"+name]
	if !ok {
		return tenant.ErrNotFound
	}
	k.Status = status
	k.UpdatedAt = time.Now()
	s.wifiKeys[tenantName+"/"+name] = k
	return nil
}

func (s *Store) DeleteWiFiKey(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.wifiKeys, tenantName+"/"+name)
	return nil
}

func (s *Store) PutDevice(_ context.Context, d tenant.Device) (tenant.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[d.Tenant]; !ok {
		return tenant.Device{}, tenant.ErrNotFound
	}
	if s.devices == nil {
		s.devices = map[string]tenant.Device{}
	}
	key := d.Tenant + "/" + d.Name
	if old, ok := s.devices[key]; ok {
		d.CreatedAt = old.CreatedAt
		// The trust class is fixed once registered; the service refuses a
		// change before it reaches the store, and the store does not silently
		// take one.
		d.TrustClass = old.TrustClass
	} else {
		d.CreatedAt = time.Now()
	}
	d.UpdatedAt = time.Now()
	s.devices[key] = d
	return d, nil
}

func (s *Store) GetDevice(_ context.Context, tenantName, name string) (tenant.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[tenantName+"/"+name]
	if !ok {
		return tenant.Device{}, tenant.ErrNotFound
	}
	return d, nil
}

func (s *Store) ListDevices(_ context.Context, tenantName string) ([]tenant.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.Device
	for _, d := range s.devices {
		if d.Tenant == tenantName {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteDevice(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, tenantName+"/"+name)
	return nil
}

func (s *Store) PutBrokerAccount(_ context.Context, a tenant.BrokerAccount) (tenant.BrokerAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[a.Tenant]; !ok {
		return tenant.BrokerAccount{}, tenant.ErrNotFound
	}
	if s.brokerAccts == nil {
		s.brokerAccts = map[string]tenant.BrokerAccount{}
	}
	key := a.Tenant + "/" + a.Name
	if old, ok := s.brokerAccts[key]; ok {
		a.CreatedAt = old.CreatedAt
	} else {
		a.CreatedAt = time.Now()
	}
	a.UpdatedAt = time.Now()
	s.brokerAccts[key] = a
	return a, nil
}

func (s *Store) GetBrokerAccount(_ context.Context, tenantName, name string) (tenant.BrokerAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.brokerAccts[tenantName+"/"+name]
	if !ok {
		return tenant.BrokerAccount{}, tenant.ErrNotFound
	}
	return a, nil
}

func (s *Store) ListBrokerAccounts(_ context.Context, tenantName string) ([]tenant.BrokerAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.BrokerAccount
	for _, a := range s.brokerAccts {
		if a.Tenant == tenantName {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetBrokerAccountStatus(_ context.Context, tenantName, name string, status tenant.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.brokerAccts[tenantName+"/"+name]
	if !ok {
		return tenant.ErrNotFound
	}
	a.Status = status
	s.brokerAccts[tenantName+"/"+name] = a
	return nil
}

func (s *Store) DeleteBrokerAccount(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.brokerAccts, tenantName+"/"+name)
	return nil
}

func (s *Store) PutRecord(_ context.Context, r tenant.ExtraRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.extraRecords == nil {
		s.extraRecords = map[string]tenant.ExtraRecord{}
	}
	s.extraRecords[r.Tenant+"/"+r.Name] = r
	return nil
}

func (s *Store) ListRecords(_ context.Context, tenantName string) ([]tenant.ExtraRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []tenant.ExtraRecord
	for _, r := range s.extraRecords {
		if r.Tenant == tenantName {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Store) DeleteRecord(_ context.Context, tenantName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.extraRecords[tenantName+"/"+name]; !ok {
		return tenant.ErrNotFound
	}
	delete(s.extraRecords, tenantName+"/"+name)
	return nil
}

// Backends records what the service asked of each backing service, and fails
// a step on demand.
type Backends struct {
	mu sync.Mutex

	DNSTenants   map[string]tenant.DNSTenant
	DNSRecords   map[string]tenant.DNSRecord
	Networks     map[string]tenant.NetworkSpec
	Workloads    map[int]tenant.WorkloadSpec
	Forwards     map[string]tenant.Forward
	States       map[string]tenant.StateTenant
	FabricClaims []tenant.Claim

	// WiFiKeys is keyed "<ssid>/<name>", which is how the controller identifies
	// a key: a name inside the profile bound to that SSID.
	WiFiKeys map[string]tenant.WiFiKeySpec

	// BrokerAccounts is keyed "<tenant>/<name>", which is how the registry
	// identifies one. What the writer would have stored is kept verbatim, so a
	// test can assert the patterns really carried the tenant's prefix.
	BrokerAccounts map[string]tenant.BrokerAccount
	// BrokerErr, when set, is returned by every Put. It stands in for the
	// ambiguous failure the retry path exists for.
	BrokerErr error

	// LogTenants is keyed by tenant name: what the log store was told this
	// tenant's users are (ADR-0027). A test can assert the index and the two
	// tokens really crossed.
	LogTenants map[string]tenant.LogTenant
	// LogErr, when set, is returned by every Put and Remove: the store being
	// unreachable while a tenant is applying.
	LogErr error
	// DashTenants is what the dashboard server was last told about each tenant,
	// and DashOrgs the organisation it gave each. DashErr fails every call.
	DashTenants map[string]tenant.DashTenant
	DashOrgs    map[string]int
	DashErr     error
	dashNext    int

	FailDNS, FailResolver, FailState, FailFabric error
	FailNetwork, FailCompute, FailWireless       error
}

func NewBackends() *Backends {
	return &Backends{
		DNSTenants:     map[string]tenant.DNSTenant{},
		DNSRecords:     map[string]tenant.DNSRecord{},
		Networks:       map[string]tenant.NetworkSpec{},
		Workloads:      map[int]tenant.WorkloadSpec{},
		Forwards:       map[string]tenant.Forward{},
		States:         map[string]tenant.StateTenant{},
		WiFiKeys:       map[string]tenant.WiFiKeySpec{},
		BrokerAccounts: map[string]tenant.BrokerAccount{},
		LogTenants:     map[string]tenant.LogTenant{},
		DashTenants:    map[string]tenant.DashTenant{},
		DashOrgs:       map[string]int{},
	}
}

// DNS, Resolver, State and Fabric expose the same recorder behind each interface.
func (b *Backends) DNS() tenant.DNS           { return dnsFake{b} }
func (b *Backends) Resolver() tenant.Resolver { return resolverFake{b} }
func (b *Backends) State() tenant.StateStore  { return stateFake{b} }
func (b *Backends) Fabric() tenant.Fabric     { return fabricFake{b} }
func (b *Backends) Network() tenant.Network   { return networkFake{b} }
func (b *Backends) Compute() tenant.Compute   { return computeFake{b} }
func (b *Backends) Wireless() tenant.Wireless { return wirelessFake{b} }

type wirelessFake struct{ b *Backends }

func (f wirelessFake) EnsureKey(_ context.Context, k tenant.WiFiKeySpec) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailWireless != nil {
		return f.b.FailWireless
	}
	if !tenant.ValidPSK(k.PSK) {
		return errors.New("psk must be 8 to 63 visible ASCII characters")
	}
	f.b.WiFiKeys[k.SSID+"/"+k.Name] = k
	return nil
}

func (f wirelessFake) RemoveKey(_ context.Context, ssid, name string) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailWireless != nil {
		return f.b.FailWireless
	}
	delete(f.b.WiFiKeys, ssid+"/"+name)
	return nil
}

type networkFake struct{ b *Backends }

func (f networkFake) Ensure(_ context.Context, n tenant.NetworkSpec) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailNetwork != nil {
		return f.b.FailNetwork
	}
	f.b.Networks[n.Zone] = n
	return nil
}

func (f networkFake) Remove(_ context.Context, n tenant.NetworkSpec) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailNetwork != nil {
		return f.b.FailNetwork
	}
	delete(f.b.Networks, n.Zone)
	return nil
}

type computeFake struct{ b *Backends }

func (f computeFake) EnsureWorkload(_ context.Context, w tenant.WorkloadSpec) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailCompute != nil {
		return f.b.FailCompute
	}
	f.b.Workloads[w.VMID] = w
	return nil
}

func (f computeFake) RemoveWorkload(_ context.Context, _ string, vmid int) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailCompute != nil {
		return f.b.FailCompute
	}
	delete(f.b.Workloads, vmid)
	return nil
}

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

func (f dnsFake) EnsureRecords(_ context.Context, zone, _ string, recs []tenant.DNSRecord) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailDNS != nil {
		return f.b.FailDNS
	}
	for _, r := range recs {
		f.b.DNSRecords[r.Name+"."+zone] = r
	}
	return nil
}

func (f dnsFake) RemoveRecords(_ context.Context, zone, _ string, recs []tenant.DNSRecord) error {
	f.b.mu.Lock()
	defer f.b.mu.Unlock()
	if f.b.FailDNS != nil {
		return f.b.FailDNS
	}
	for _, r := range recs {
		delete(f.b.DNSRecords, r.Name+"."+zone)
	}
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
		DashboardURL:      "https://dv02obs001v01.mobile.deevnet.net:3000",
		StateBucket:       "tf-state",
		ResolverForwardTo: "10.20.25.21",
		WorkloadResolver:  "10.20.50.1",
		TenantVMIDBase:    2000,
		MACNamespace:      "02:de:20",
		TemplatePrefix:    "fedora-server-",
		Storage:           "local-lvm",
		Disk:              "scsi0",
		CIUser:            "a_autoprov",
		TrustClasses: map[string]tenant.TrustClass{
			"iot":        {Name: "iot", SSID: "DVNTM-IOT", VLAN: 30},
			"iot_vendor": {Name: "iot_vendor", SSID: "DVNTM-IOTV", VLAN: 31},
		},
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
type brokerWriter struct{ b *Backends }

// BrokerWriter returns a stand-in for the program on the messaging VM.
func (b *Backends) BrokerWriter() tenant.BrokerWriter { return &brokerWriter{b} }

func (w *brokerWriter) Put(_ context.Context, a tenant.BrokerAccount) error {
	if w.b.BrokerErr != nil {
		return w.b.BrokerErr
	}
	w.b.BrokerAccounts[a.Tenant+"/"+a.Name] = a
	return nil
}

func (w *brokerWriter) Remove(_ context.Context, tenantName, name string) error {
	if w.b.BrokerErr != nil {
		return w.b.BrokerErr
	}
	delete(w.b.BrokerAccounts, tenantName+"/"+name)
	return nil
}

type dashboards struct{ b *Backends }

// Dashboards returns a stand-in for the dashboard server. Organisations are
// numbered from 2, as Grafana's are: 1 is the operator's.
func (b *Backends) Dashboards() tenant.Dashboards { return &dashboards{b} }

func (d *dashboards) Ensure(_ context.Context, t tenant.DashTenant) (int, error) {
	if d.b.DashErr != nil {
		return 0, d.b.DashErr
	}
	d.b.mu.Lock()
	defer d.b.mu.Unlock()
	org, ok := d.b.DashOrgs[t.Name]
	if !ok {
		d.b.dashNext++
		org = d.b.dashNext + 1
		d.b.DashOrgs[t.Name] = org
	}
	d.b.DashTenants[t.Name] = t
	return org, nil
}

func (d *dashboards) Remove(_ context.Context, name string) error {
	if d.b.DashErr != nil {
		return d.b.DashErr
	}
	d.b.mu.Lock()
	defer d.b.mu.Unlock()
	delete(d.b.DashTenants, name)
	delete(d.b.DashOrgs, name)
	return nil
}

type logWriter struct{ b *Backends }

// LogWriter returns a stand-in for the program on the observability store.
func (b *Backends) LogWriter() tenant.LogWriter { return &logWriter{b} }

func (w *logWriter) Put(_ context.Context, lt tenant.LogTenant) error {
	if w.b.LogErr != nil {
		return w.b.LogErr
	}
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	w.b.LogTenants[lt.Name] = lt
	return nil
}

func (w *logWriter) Remove(_ context.Context, name string, _ int) error {
	if w.b.LogErr != nil {
		return w.b.LogErr
	}
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	delete(w.b.LogTenants, name)
	return nil
}

func NewService() (*tenant.Service, *Store, *Backends) {
	st := NewStore()
	b := NewBackends()
	tokens, err := tenant.NewTokens(TokenKey)
	if err != nil {
		panic(err)
	}
	return &tenant.Service{
		Site:         MobileSite(),
		Store:        st,
		DNS:          b.DNS(),
		Resolver:     b.Resolver(),
		State:        b.State(),
		Fabric:       b.Fabric(),
		Network:      b.Network(),
		Compute:      b.Compute(),
		Wireless:     b.Wireless(),
		BrokerWriter: b.BrokerWriter(),
		LogWriter:    b.LogWriter(),
		Dashboards:   b.Dashboards(),
		Tokens:       tokens,
		Enroller:     &Enroller{},
	}, st, b
}
