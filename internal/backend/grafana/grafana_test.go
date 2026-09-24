package grafana

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The contract's UIDs are what a dashboard names. A change here breaks every
// tenant's dashboards, on every site and every Pi, so it is pinned by a test.
func TestDataSourceContractIsPinned(t *testing.T) {
	want := map[string]int{"deevnet-logs-workloads": 0, "deevnet-logs-platform": 1, "deevnet-logs-devices": 2}
	if len(DataSources) != len(want) {
		t.Fatalf("%d data sources, want %d", len(DataSources), len(want))
	}
	defaults := 0
	for _, ds := range DataSources {
		p, ok := want[ds.UID]
		if !ok || p != ds.Project {
			t.Errorf("data source %s -> project %d is not in the contract", ds.UID, ds.Project)
		}
		if ds.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Errorf("%d default data sources, want 1", defaults)
	}
}

// The partition header carries index-project, and the token goes in as a
// bearer. Neither may ever be in jsonData, which the server hands back to
// anyone who can read the data source.
func TestDataSourceBodyKeepsTheTokenSecure(t *testing.T) {
	b := DataSourceBody(DataSources[2], 3, "tok", "https://store:8427", "CA")
	sec := b["secureJsonData"].(map[string]string)
	if sec["httpHeaderValue1"] != "Bearer tok" || sec["httpHeaderValue2"] != "3-2" {
		t.Fatalf("secureJsonData = %v", sec)
	}
	if fmt.Sprint(b["jsonData"]) != fmt.Sprint(map[string]any{
		"httpHeaderName1": "Authorization", "httpHeaderName2": PartitionHeader, "tlsAuthWithCACert": true,
	}) {
		t.Fatalf("jsonData = %v", b["jsonData"])
	}
	if strings.Contains(fmt.Sprint(b["jsonData"]), "tok") {
		t.Fatal("the token is in jsonData")
	}
}

// A tenant named for the admin would have its password reset to the tenant's.
func TestRefusesTheAdminsName(t *testing.T) {
	c := &Client{cfg: Config{AdminUser: "admin"}}
	if _, err := c.Ensure(context.Background(), tenant.DashTenant{Name: "admin"}); err == nil {
		t.Fatal("ensure accepted a tenant named for the server admin")
	}
	if err := c.Remove(context.Background(), "admin"); err == nil {
		t.Fatal("remove accepted a tenant named for the server admin")
	}
}

// Needs a Grafana the test may write to, over HTTPS, with the VictoriaLogs
// plugin installed: DEEVNET_TEST_GRAFANA_URL, DEEVNET_TEST_GRAFANA_PASSWORD
// (the admin's) and DEEVNET_TEST_GRAFANA_CA. `make test-integration` starts one.
func testClient(t *testing.T) *Client {
	t.Helper()
	u, pw, ca := os.Getenv("DEEVNET_TEST_GRAFANA_URL"), os.Getenv("DEEVNET_TEST_GRAFANA_PASSWORD"), os.Getenv("DEEVNET_TEST_GRAFANA_CA")
	if u == "" || pw == "" || ca == "" {
		t.Skip("DEEVNET_TEST_GRAFANA_URL / _PASSWORD / _CA not set")
	}
	c, err := New(Config{URL: u, AdminUser: "admin", AdminPassword: pw, CAFile: ca, LogEndpoint: "https://store.invalid:8427"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// asUser makes a call as the tenant's own login.
func asUser(t *testing.T, c *Client, login, pw, method, path string, org int, in, out any) error {
	t.Helper()
	u := *c
	u.cfg.AdminUser, u.cfg.AdminPassword = login, pw
	return u.do(context.Background(), method, path, org, in, out)
}

func TestEnsureBuildsTheTenantsOrganisationAndRemoves(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	tt := tenant.DashTenant{Name: "tprobe", Index: 7, Password: "first-password-0123456789", ReadToken: "read-token-7"}
	_ = c.Remove(ctx, tt.Name)
	t.Cleanup(func() { _ = c.Remove(context.Background(), tt.Name) })

	org, err := c.Ensure(ctx, tt)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if org <= 1 {
		t.Fatalf("org = %d, want a tenant organisation", org)
	}
	// A second ensure changes nothing and gives the same organisation.
	again, err := c.Ensure(ctx, tt)
	if err != nil || again != org {
		t.Fatalf("ensure again = %d, %v; want %d", again, err, org)
	}

	// The login is an Editor in its organisation and a member of nothing else.
	var orgs []struct {
		OrgID int    `json:"orgId"`
		Role  string `json:"role"`
	}
	if err := asUser(t, c, tt.Name, tt.Password, http.MethodGet, "/api/user/orgs", 0, nil, &orgs); err != nil {
		t.Fatalf("the login cannot sign in: %v", err)
	}
	if len(orgs) != 1 || orgs[0].OrgID != org || orgs[0].Role != TenantRole {
		t.Fatalf("login's organisations = %+v, want only %d as %s", orgs, org, TenantRole)
	}

	// It sees the three data sources by their fixed UIDs, and cannot make one.
	for _, ds := range DataSources {
		var got struct {
			Type     string         `json:"type"`
			JSONData map[string]any `json:"jsonData"`
		}
		if err := asUser(t, c, tt.Name, tt.Password, http.MethodGet, "/api/datasources/uid/"+ds.UID, org, nil, &got); err != nil {
			t.Fatalf("data source %s: %v", ds.UID, err)
		}
		if got.Type != PluginID {
			t.Errorf("data source %s is %q", ds.UID, got.Type)
		}
		if strings.Contains(fmt.Sprint(got.JSONData), tt.ReadToken) {
			t.Errorf("data source %s hands the token back", ds.UID)
		}
	}
	err = asUser(t, c, tt.Name, tt.Password, http.MethodPost, "/api/datasources", org,
		map[string]any{"name": "mine", "type": "prometheus", "access": "proxy", "url": "http://169.254.169.254/"}, nil)
	if !isStatus(err, 403) {
		t.Fatalf("an Editor creating a data source got %v, want 403", err)
	}

	// A drifted password is put back.
	tt2 := tt
	tt2.Password = "second-password-0123456789"
	if _, err := c.Ensure(ctx, tt2); err != nil {
		t.Fatalf("ensure with a new password: %v", err)
	}
	if err := asUser(t, c, tt.Name, tt2.Password, http.MethodGet, "/api/user", 0, nil, nil); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}

	// A login someone added to organisation 1 is taken out again.
	if err := c.do(ctx, http.MethodPost, "/api/orgs/1/users", 0, map[string]string{"loginOrEmail": tt.Name, "role": "Viewer"}, nil); err != nil {
		t.Fatalf("adding to org 1: %v", err)
	}
	if _, err := c.Ensure(ctx, tt2); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	orgs = nil
	if err := asUser(t, c, tt.Name, tt2.Password, http.MethodGet, "/api/user/orgs", 0, nil, &orgs); err != nil || len(orgs) != 1 {
		t.Fatalf("after ensure the login is in %+v (%v), want one organisation", orgs, err)
	}

	if err := c.Remove(ctx, tt.Name); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.Remove(ctx, tt.Name); err != nil {
		t.Fatalf("remove again: %v", err)
	}
	if _, err := c.lookupOrg(ctx, tt.Name); err != errNotFound {
		t.Fatalf("organisation after remove: %v", err)
	}
	if _, err := c.lookupUser(ctx, tt.Name); err != errNotFound {
		t.Fatalf("login after remove: %v", err)
	}
}
