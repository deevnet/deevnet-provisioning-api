package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func TestClaimsFromZonesAndVNets(t *testing.T) {
	zonesJSON := `{"data":[
	  {"zone":"eds","type":"evpn","vrf-vxlan":10001,"controller":"evpn1"},
	  {"zone":"tdemo","type":"evpn","state":"new","pending":{"vrf-vxlan":"10002"}},
	  {"zone":"simple","type":"simple"},
	  {"zone":"stray","type":"evpn","vrf-vxlan":999}
	]}`
	vnetsJSON := `{"data":[
	  {"vnet":"eds0","zone":"eds","tag":20010},
	  {"vnet":"orphan0","zone":"orphan","tag":"20070"},
	  {"vnet":"moved0","zone":"x","tag":20080,"pending":{"tag":20090,"zone":"y"}}
	]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=audit@pve!api=s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("pending") != "1" {
			t.Errorf("%s asked without pending=1", r.URL.Path)
		}
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			_, _ = w.Write([]byte(zonesJSON))
		case "/api2/json/cluster/sdn/vnets":
			_, _ = w.Write([]byte(vnetsJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "audit@pve!api", "s3cret", tenanttest.MobileSite(), false)
	got, err := c.Claims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []tenant.Claim{
		{Index: 1, Zone: "eds"},
		{Index: 2, Zone: "tdemo"},
		{Index: 7, Zone: "orphan"},
		{Index: 8, Zone: "x"},
		{Index: 9, Zone: "y"},
	}
	key := func(c tenant.Claim) string { b, _ := json.Marshal(c); return string(b) }
	slices.SortFunc(got, func(a, b tenant.Claim) int { return strings.Compare(key(a), key(b)) })
	slices.SortFunc(want, func(a, b tenant.Claim) int { return strings.Compare(key(a), key(b)) })
	if !slices.Equal(got, want) {
		t.Fatalf("claims\n got %v\nwant %v", got, want)
	}
}

func TestAbsentSDNObjectReadsAsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What PVE 8.4 answers for a zone that is not there.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"sdn zone 'tprobe' does not exist
","data":null}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	var out map[string]any
	if err := c.get(context.Background(), "/cluster/sdn/zones/tprobe", &out); !errors.Is(err, errNotFound) {
		t.Fatalf("err = %v, want errNotFound", err)
	}
	// A real 500 is still an error.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"storage is not online"}`))
	}))
	defer srv2.Close()
	c2 := New(srv2.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	if err := c2.get(context.Background(), "/cluster/sdn/zones/tprobe", &out); err == nil || errors.Is(err, errNotFound) {
		t.Fatalf("err = %v, want a real failure", err)
	}
}

// Read-only against a real node: DEEVNET_TEST_PVE_URL (e.g.
// https://10.20.99.22:8006), _TOKEN_ID and _TOKEN_SECRET.
func TestClaimsAgainstARealNode(t *testing.T) {
	u := os.Getenv("DEEVNET_TEST_PVE_URL")
	if u == "" {
		t.Skip("DEEVNET_TEST_PVE_URL not set")
	}
	c := New(u, os.Getenv("DEEVNET_TEST_PVE_TOKEN_ID"), os.Getenv("DEEVNET_TEST_PVE_TOKEN_SECRET"), tenanttest.MobileSite(), true)
	claims, err := c.Claims(context.Background())
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	t.Logf("fabric claims: %v", claims)
}

// Proxmox unescapes sshkeys with URI::Escape's uri_unescape: %XX becomes the
// byte and '+' stays '+'. url.PathUnescape does the same, so what it yields
// is what lands in the workload's authorized_keys.
func TestSSHKeysReachProxmoxIntact(t *testing.T) {
	keys := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx+a/b=c tenant@laptop",
		"ssh-rsa AAAAB3NzaC1yc2E+/== operator key",
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			raw := r.PostForm.Get("sshkeys")
			dec, err := url.PathUnescape(raw)
			if err != nil {
				t.Fatalf("sshkeys %q: %v", raw, err)
			}
			got = dec
		}
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	w := tenant.WorkloadSpec{Node: "hv02", VMID: 2040, Cores: 2, MemoryMB: 2048,
		MAC: "02:00:00:00:00:01", Bridge: "tdemo0", Address: "10.20.129.10/24", Gateway: "10.20.129.1",
		SSHKeys: keys, CIUser: "tenant"}
	if err := c.configureWorkload(context.Background(), w, false); err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(keys, "\n") + "\n"; got != want {
		t.Fatalf("authorized_keys\n got %q\nwant %q", got, want)
	}
}

// A workload boots straight to ready. With Proxmox's default (ciupgrade on),
// cloud-init runs a full package upgrade on first boot - hundreds of packages,
// minutes long, and on CHG-0028's eds rebuild it took the network down half
// way and never came back. Updates are the tenant's, on its own schedule.
func TestWorkloadsDoNotUpgradeOnFirstBoot(t *testing.T) {
	var got string
	var set bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			_ = r.ParseForm()
			got, set = r.PostForm.Get("ciupgrade"), r.PostForm.Has("ciupgrade")
		}
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	w := tenant.WorkloadSpec{Node: "hv02", VMID: 2040, Cores: 2, MemoryMB: 2048,
		MAC: "02:00:00:00:00:01", Bridge: "tdemo0", Address: "10.20.129.10/24", Gateway: "10.20.129.1"}
	if err := c.configureWorkload(context.Background(), w, false); err != nil {
		t.Fatal(err)
	}
	if !set || got != "0" {
		t.Fatalf("ciupgrade = %q (set=%v), want \"0\"", got, set)
	}
}
