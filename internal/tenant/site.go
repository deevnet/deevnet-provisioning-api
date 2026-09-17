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
)

// ADR-0002: the overlay block is a /18, so one site holds 63 tenant indexes.
// 63 is reserved for drills (ADR-0006 §3, ADR-0015 §3) and never allocated.
const (
	MinIndex       = 1
	MaxAllocatable = 62
	ReservedIndex  = 63

	vnetsPerTenant  = 10
	tsigAlgorithm   = "hmac-sha256"
	statePrefixRoot = "tenants"
	egressVRFPrefix = "vrf_"
)

// The PVE SDN zone ID is the tenant name verbatim, and PVE caps zone IDs at 8
// characters. The tenant module validates the same pattern.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`)

// ValidName reports whether name can be a tenant: a PVE SDN zone ID, which is
// also a DNS label, a MinIO user and a VRF suffix.
func ValidName(name string) bool { return nameRE.MatchString(name) }

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

	// Where the core router's resolver forwards tenant zones: the address of
	// the tenant DNS server.
	ResolverForwardTo string
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
	}
	return nil
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
