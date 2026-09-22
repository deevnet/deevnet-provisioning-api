// Package tenant creates, restores and removes tenants (ADR-0015).
//
// It owns the rules: which index a tenant gets, what "free" means, when a
// restore keeps its index and when it is issued a new one, and the order the
// backing services are brought into line. It holds no HTTP and no SQL; the
// server and the store are on either side of it, and the backends are behind
// interfaces so tests run without PowerDNS, the router, MinIO or Proxmox.
package tenant

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ADR-0002: the overlay block is a /18, so one site holds 63 tenant indexes.
// 63 is reserved for drills (ADR-0006 §3, ADR-0015 §3) and never allocated.
const (
	MinIndex       = 1
	MaxAllocatable = 62
	ReservedIndex  = 63

	vnetsPerTenant = 10
	// Workload ordinals per tenant. Addresses run from .10, and VMIDs from the
	// site's tenant base, both by ordinal.
	MaxWorkloads    = 40
	tsigAlgorithm   = "hmac-sha256"
	statePrefixRoot = "tenants"
	egressVRFPrefix = "vrf_"
)

// The PVE SDN zone ID is the tenant name verbatim, and PVE caps zone IDs at 8
// characters. The tenant module validates the same pattern.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`)

// A workload or record name is a DNS label under the tenant's zone.
var workloadNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)

// ValidWorkloadName reports whether name can be a workload or a published name.
func ValidWorkloadName(name string) bool {
	return workloadNameRE.MatchString(name) && !strings.HasSuffix(name, "-")
}

// ValidName reports whether name can be a tenant: a PVE SDN zone ID, which is
// also a DNS label, a MinIO user and a VRF suffix.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// TrustClass is one IoT trust class: the SSID a device joins and the VLAN its
// key is bound to (ADR-0011 §3).
//
// These are the substrate's fixed segments, not per-tenant ones. Every tenant's
// key for a class carries the same SSID and the same VLAN, and a tenant never
// chooses either - which is what keeps a tenant network off the air and leaves
// ADR-0011 Option B rejected.
//
// Inventory is still the only declaration of them (ADR-0009). This copy is
// projected into the API's environment by the deployment role, the same way the
// fabric controller and the MAC namespace are, rather than being a second place
// they are decided.
type TrustClass struct {
	Name string
	SSID string
	VLAN int
}

// Site is one site's constants. Every per-tenant identifier derives from these
// and the index (ADR-0002); one API serves one site (ADR-0015 §8).
type Site struct {
	// Label in the zone name: mobile or home.
	Name string
	// Second octet of the site block: 20 = mobile, 10 = home.
	Octet int
	// deevnet.net
	RootDomain string
	// ADR-0002 VNI bases: 10000/20000 on mobile, 11000/21000 on home.
	VRFVNIBase  int
	VNetVNIBase int

	// The fabric attachment every tenant on this single-member fabric gets
	// (ADR-0006 §2, now returned instead of rendered).
	ControllerID string
	Node         string

	// Where tenants send RFC 2136 updates, by name, and the apex NS the
	// substrate owns in every tenant zone (ADR-0005).
	DNSUpdateServer string
	DNSApexNS       string
	// Networks allowed to attempt an update. TSIG decides the outcome.
	DNSUpdateFrom []string

	// The state store tenants are offered (ADR-0007).
	StateEndpoint string
	StateBucket   string

	// The log store tenants are offered (ADR-0027). Optional: a site without
	// one issues no log tokens, and the tenant view simply carries no
	// endpoint. It is not validated below for that reason.
	LogEndpoint string

	// TrustClasses this site serves, by name. Empty means the site issues no
	// Wi-Fi keys, which is a legitimate site: one without a wireless
	// controller, which is what was deployed before CHG-0013.
	TrustClasses map[string]TrustClass

	// Where the core router's resolver forwards tenant zones: the address of
	// the tenant DNS server. Authoritative, so it answers tenant zones and
	// REFUSES everything else - which is what a forward target is for, and
	// why it is not what a workload may point at. See WorkloadResolver.
	ResolverForwardTo string

	// What a workload is given as its cloud-init nameserver: a recursor, so
	// the workload can resolve public names, substrate names and its own
	// tenant's names alike. The tenant_transit gateway is the first substrate
	// hop a tenant's traffic reaches, and the core router answering there both
	// recurses and forwards tenant zones to ResolverForwardTo.
	WorkloadResolver string

	// --- Workloads (ADR-0015 §12) ---
	// First VMID of the site's tenant band. A workload's VMID is
	// TenantVMIDBase + index*MaxWorkloads + ordinal, so it is stable across
	// rebuilds and never collides with the management band.
	TenantVMIDBase int
	// 02:de:<octet> - the MAC derives from the VMID (standards/mac-naming).
	MACNamespace string
	// Template name prefix, datastore and the disk grown when a workload asks
	// for more than the template's size.
	TemplatePrefix string
	Storage        string
	Disk           string
	// The account cloud-init creates for the tenant's keys.
	CIUser string
}

// Validate refuses a site the API could only half serve.
func (s Site) Validate() error {
	switch {
	case s.Name == "":
		return fmt.Errorf("site name is empty")
	case s.Octet < 1 || s.Octet > 254:
		return fmt.Errorf("site octet %d is out of range", s.Octet)
	case s.RootDomain == "":
		return fmt.Errorf("root domain is empty")
	case s.VRFVNIBase <= 0 || s.VNetVNIBase <= 0:
		return fmt.Errorf("VNI bases must be positive")
	case s.ControllerID == "" || s.Node == "":
		return fmt.Errorf("fabric controller and node are required")
	case s.DNSUpdateServer == "" || s.DNSApexNS == "":
		return fmt.Errorf("DNS update server and apex NS are required")
	case len(s.DNSUpdateFrom) == 0:
		return fmt.Errorf("at least one DNS update network is required")
	case s.StateEndpoint == "" || s.StateBucket == "":
		return fmt.Errorf("state endpoint and bucket are required")
	case s.ResolverForwardTo == "":
		return fmt.Errorf("resolver forward target is required")
	case s.WorkloadResolver == "":
		return fmt.Errorf("workload resolver is required")
	case s.TenantVMIDBase <= 0:
		return fmt.Errorf("tenant VMID base must be positive")
	case s.MACNamespace == "":
		return fmt.Errorf("MAC namespace is required")
	case s.TemplatePrefix == "":
		return fmt.Errorf("template prefix is required")
	case s.Disk == "":
		return fmt.Errorf("the disk to grow is required")
	}
	// Trust classes are optional, but a half-declared one would bind a key to
	// the wrong place, so a declared one has to be complete.
	for name, tc := range s.TrustClasses {
		switch {
		case tc.SSID == "":
			return fmt.Errorf("trust class %q has no SSID", name)
		case tc.VLAN < 1 || tc.VLAN > 4094:
			return fmt.Errorf("trust class %q has VLAN %d, outside 1-4094", name, tc.VLAN)
		}
	}
	return nil
}

// TrustClass returns the named trust class this site serves.
func (s Site) TrustClass(name string) (TrustClass, bool) {
	tc, ok := s.TrustClasses[name]
	return tc, ok
}

// TrustClassNames returns the classes this site serves, sorted, for an error
// message that tells a tenant what it may actually ask for.
func (s Site) TrustClassNames() []string {
	out := make([]string, 0, len(s.TrustClasses))
	for name := range s.TrustClasses {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Numbering is everything ADR-0002 derives from one index.
type Numbering struct {
	Index       int    `json:"index"`
	VRFVNI      int    `json:"vrf_vni"`
	VNetVNIBase int    `json:"vnet_vni_base"`
	Subnet      string `json:"subnet"`
	Gateway     string `json:"gateway"`
	ReverseZone string `json:"reverse_zone"`
}

func (s Site) Numbering(index int) Numbering {
	third := 128 + index
	return Numbering{
		Index:       index,
		VRFVNI:      s.VRFVNIBase + index,
		VNetVNIBase: s.VNetVNIBase + index*vnetsPerTenant,
		Subnet:      fmt.Sprintf("10.%d.%d.0/24", s.Octet, third),
		Gateway:     fmt.Sprintf("10.%d.%d.1", s.Octet, third),
		ReverseZone: fmt.Sprintf("%d.%d.10.in-addr.arpa", third, s.Octet),
	}
}

// Zone is a tenant's forward zone, <tenant>.<site>.<root>.
func (s Site) Zone(name string) string {
	return fmt.Sprintf("%s.%s.%s", name, s.Name, s.RootDomain)
}

// IndexForVRFVNI maps a VRF VNI seen on the fabric back to an index, or 0 when
// the VNI is not a tenant VNI on this site.
func (s Site) IndexForVRFVNI(vni int) int {
	n := vni - s.VRFVNIBase
	if n < MinIndex || n > ReservedIndex {
		return 0
	}
	return n
}

// IndexForVNetTag maps a VNet tag back to the index whose VNet range holds it,
// or 0.
func (s Site) IndexForVNetTag(tag int) int {
	off := tag - s.VNetVNIBase
	if off < 0 {
		return 0
	}
	n := off / vnetsPerTenant
	if n < MinIndex || n > ReservedIndex {
		return 0
	}
	return n
}

func (s Site) statePrefix(name string) string {
	return fmt.Sprintf("%s/%s/", statePrefixRoot, name)
}

// Network is the fabric objects for one tenant. VNet ids follow the tenant
// module's rule: the first six characters of the name, then the VNet's number.
func (s Site) Network(name string, index int) NetworkSpec {
	n := s.Numbering(index)
	short := name
	if len(short) > 6 {
		short = short[:6]
	}
	return NetworkSpec{
		Zone:       name,
		Controller: s.ControllerID,
		Node:       s.Node,
		VRFVNI:     n.VRFVNI,
		VNets:      []VNetSpec{{ID: fmt.Sprintf("%s%d", short, 0), Tag: n.VNetVNIBase}},
		Subnet:     n.Subnet,
		Gateway:    n.Gateway,
	}
}

// WorkloadVMID is the VMID of a tenant's workload: stable, and derived rather
// than allocated.
func (s Site) WorkloadVMID(index, ordinal int) int {
	return s.TenantVMIDBase + index*MaxWorkloads + ordinal
}

// WorkloadAddress is the workload's address: .10 upwards, leaving .1 for the
// anycast gateway and .2-.9 for the fabric.
func (s Site) WorkloadAddress(index, ordinal int) string {
	return fmt.Sprintf("10.%d.%d.%d", s.Octet, 128+index, 10+ordinal)
}

// MAC derives a VMID's MAC (standards/mac-naming §5):
// 02:de:<site octet>:(vmid >> 16):(vmid >> 8 & 0xff):(vmid & 0xff).
func (s Site) MAC(vmid int) string {
	return fmt.Sprintf("%s:%02x:%02x:%02x", s.MACNamespace, (vmid>>16)&0xff, (vmid>>8)&0xff, vmid&0xff)
}
