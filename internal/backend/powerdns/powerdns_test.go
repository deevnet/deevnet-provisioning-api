package powerdns

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Needs a PowerDNS Authoritative with its HTTP API on, which the test may write
// to: DEEVNET_TEST_PDNS_URL (e.g. http://127.0.0.1:18081) and
// DEEVNET_TEST_PDNS_KEY. `make test-integration` starts one.
func testClient(t *testing.T) *Client {
	t.Helper()
	u, k := os.Getenv("DEEVNET_TEST_PDNS_URL"), os.Getenv("DEEVNET_TEST_PDNS_KEY")
	if u == "" || k == "" {
		t.Skip("DEEVNET_TEST_PDNS_URL / DEEVNET_TEST_PDNS_KEY not set")
	}
	return New(u, k)
}

func secret(fill string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(fill, 32)))
}

func probeTenant() tenant.DNSTenant {
	return tenant.DNSTenant{
		KeyName:    "tprobe",
		Algorithm:  "hmac-sha256",
		Secret:     secret("a"),
		Zones:      []string{"tprobe.mobile.deevnet.net", "190.20.10.in-addr.arpa"},
		ApexNS:     "dv02idn001v01.mobile.deevnet.net",
		UpdateFrom: []string{"10.20.99.0/24", "10.20.50.0/24"},
	}
}

func TestEnsureCreatesAdoptsAndRemoves(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	tt := probeTenant()
	_ = c.Remove(ctx, tt)
	t.Cleanup(func() { _ = c.Remove(context.Background(), tt) })

	if err := c.Ensure(ctx, tt); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// A second ensure is a no-op, not a 409.
	if err := c.Ensure(ctx, tt); err != nil {
		t.Fatalf("ensure again: %v", err)
	}

	var key tsigKey
	if err := c.do(ctx, http.MethodGet, "/tsigkeys/tprobe.", nil, &key); err != nil || key.Key != tt.Secret {
		t.Fatalf("key = %+v (%v), want the supplied secret", key.Name, err)
	}
	for _, z := range tt.Zones {
		checkZone(t, c, z, tt)
	}

	// A restore brings a different secret: the key is replaced, not duplicated.
	tt.Secret = secret("b")
	tt.UpdateFrom = []string{"10.20.50.0/24"}
	if err := c.Ensure(ctx, tt); err != nil {
		t.Fatalf("ensure rotated: %v", err)
	}
	if err := c.do(ctx, http.MethodGet, "/tsigkeys/tprobe.", nil, &key); err != nil || key.Key != tt.Secret {
		t.Fatalf("key not rotated (%v)", err)
	}
	checkZone(t, c, tt.Zones[0], tt)

	if err := c.Remove(ctx, tt); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(fqdn(tt.Zones[0])), nil, nil); !errors.Is(err, errNotFound) {
		t.Fatalf("zone survived remove: %v", err)
	}
	if err := c.Remove(ctx, tt); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

// A zone created the way `pdnsutil create-zone` did before default-soa-content
// was set: the placeholder primary and no apex NS (ADR-0005).
func TestEnsureFixesAPlaceholderApex(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	tt := probeTenant()
	tt.Zones = tt.Zones[:1]
	_ = c.Remove(ctx, tt)
	t.Cleanup(func() { _ = c.Remove(context.Background(), tt) })

	apex := fqdn(tt.Zones[0])
	err := c.do(ctx, http.MethodPost, "/zones", map[string]any{
		"name": apex, "kind": "Native", "nameservers": []string{},
		"rrsets": []rrset{{Name: apex, Type: "SOA", TTL: 3600, Records: []record{{
			Content: "a.misconfigured.dns.server.invalid. hostmaster.tprobe.mobile.deevnet.net. 41 10800 3600 604800 3600",
		}}}},
	}, nil)
	if err != nil {
		t.Fatalf("seeding the placeholder zone: %v", err)
	}

	// A tenant record at another name, with its own NS: never touched.
	err = c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(apex), map[string]any{"rrsets": []rrset{{
		Name: "sub." + apex, Type: "NS", TTL: 60, ChangeType: "REPLACE", Records: []record{{Content: "ns.example.net."}},
	}}}, nil)
	if err != nil {
		t.Fatalf("seeding a delegated subzone: %v", err)
	}

	if err := c.Ensure(ctx, tt); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	z := checkZone(t, c, tt.Zones[0], tt)
	for _, rr := range z.RRsets {
		if rr.Name == "sub."+apex && rr.Type == "NS" && (len(rr.Records) != 1 || rr.Records[0].Content != "ns.example.net.") {
			t.Errorf("the tenant's own NS below the apex was changed: %+v", rr)
		}
	}
}

func checkZone(t *testing.T, c *Client, name string, tt tenant.DNSTenant) zone {
	t.Helper()
	ctx := context.Background()
	apex := fqdn(name)
	var z zone
	if err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(apex), nil, &z); err != nil {
		t.Fatalf("zone %s: %v", name, err)
	}
	var sawSOA, sawNS bool
	for _, rr := range z.RRsets {
		if rr.Name != apex {
			continue
		}
		switch rr.Type {
		case "SOA":
			sawSOA = true
			if f := strings.Fields(rr.Records[0].Content); f[0] != fqdn(tt.ApexNS) {
				t.Errorf("%s SOA primary = %s, want %s", name, f[0], fqdn(tt.ApexNS))
			}
		case "NS":
			sawNS = true
			if len(rr.Records) != 1 || rr.Records[0].Content != fqdn(tt.ApexNS) {
				t.Errorf("%s apex NS = %+v, want only %s", name, rr.Records, fqdn(tt.ApexNS))
			}
		}
	}
	if !sawSOA || !sawNS {
		t.Errorf("%s: SOA %v NS %v, want both", name, sawSOA, sawNS)
	}
	for kind, want := range map[string][]string{"TSIG-ALLOW-DNSUPDATE": {tt.KeyName}, "ALLOW-DNSUPDATE-FROM": tt.UpdateFrom} {
		var m metadata
		if err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(apex)+"/metadata/"+kind, nil, &m); err != nil || !sameSet(m.Metadata, want) {
			t.Errorf("%s %s = %v (%v), want %v", name, kind, m.Metadata, err, want)
		}
	}
	return z
}

// An index passed to a new tenant: its reverse zone still holds the previous
// tenant's records and is bound to the previous tenant's key.
func TestEnsurePurgesAZoneHandedToAnotherTenant(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	old := probeTenant()
	old.Zones = []string{"191.20.10.in-addr.arpa"}
	next := old
	next.KeyName = "tnext"
	next.Secret = secret("c")
	_ = c.Remove(ctx, old)
	_ = c.Remove(ctx, next)
	t.Cleanup(func() { _ = c.Remove(context.Background(), old); _ = c.Remove(context.Background(), next) })

	if err := c.Ensure(ctx, old); err != nil {
		t.Fatal(err)
	}
	apex := fqdn(old.Zones[0])
	ptr := rrset{Name: "10." + apex, Type: "PTR", TTL: 60, ChangeType: "REPLACE", Records: []record{{Content: "tprobe-1.tprobe.mobile.deevnet.net."}}}
	if err := c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(apex), map[string]any{"rrsets": []rrset{ptr}}, nil); err != nil {
		t.Fatal(err)
	}

	// The same tenant ensuring again keeps its records.
	if err := c.Ensure(ctx, old); err != nil {
		t.Fatal(err)
	}
	if !hasRRset(t, c, apex, "10."+apex, "PTR") {
		t.Fatal("a tenant's own records were purged")
	}

	if err := c.Ensure(ctx, next); err != nil {
		t.Fatal(err)
	}
	if hasRRset(t, c, apex, "10."+apex, "PTR") {
		t.Fatal("the new tenant inherited the previous tenant's PTR")
	}
	checkZone(t, c, old.Zones[0], next)
}

func hasRRset(t *testing.T, c *Client, zoneName, name, typ string) bool {
	t.Helper()
	var z zone
	if err := c.do(context.Background(), http.MethodGet, "/zones/"+url.PathEscape(zoneName), nil, &z); err != nil {
		t.Fatal(err)
	}
	for _, rr := range z.RRsets {
		if rr.Name == name && rr.Type == typ {
			return true
		}
	}
	return false
}
