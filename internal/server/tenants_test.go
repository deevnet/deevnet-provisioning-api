package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func tenantServer(t *testing.T) (http.Handler, *tenanttest.Store, *tenanttest.Backends) {
	t.Helper()
	svc, st, b := tenanttest.NewService()
	svc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(Config{
		Token:   "s3cret",
		DB:      fakeDB{},
		Logger:  svc.Logger,
		Tenants: svc,
	}), st, b
}

func call(t *testing.T, h http.Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	return callAs(t, h, "s3cret", method, path, body)
}

func callAs(t *testing.T, h http.Handler, token, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: body is not JSON: %s", method, path, rec.Body.String())
		}
	}
	return rec, out
}

func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func TestTenantRoutesNeedTheToken(t *testing.T) {
	h, _, _ := tenantServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/tenants", strings.NewReader(`{"name":"tdemo"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCreateReturnsEverythingTheTenantNeeds(t *testing.T) {
	h, _, _ := tenantServer(t)
	rec, body := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d %v, want 201", rec.Code, body)
	}
	checks := map[string]any{
		"name":    "tdemo",
		"index":   float64(1),
		"status":  "ready",
		"outcome": "created",
	}
	for k, want := range checks {
		if body[k] != want {
			t.Errorf("%s = %v, want %v", k, body[k], want)
		}
	}
	nested := []struct {
		path []string
		want any
	}{
		{[]string{"network", "subnet"}, "10.20.129.0/24"},
		{[]string{"network", "vrf_vni"}, float64(10001)},
		{[]string{"fabric", "controller_id"}, "evpn1"},
		{[]string{"fabric", "node"}, "dv02hyp002p02"},
		{[]string{"dns", "zone"}, "tdemo.mobile.deevnet.net"},
		{[]string{"dns", "reverse_zone"}, "129.20.10.in-addr.arpa"},
		{[]string{"dns", "update_server"}, "tdns.mobile.deevnet.net"},
		{[]string{"state", "key_prefix"}, "tenants/tdemo/"},
		{[]string{"state", "access_key"}, "tdemo"},
	}
	for _, c := range nested {
		if got := dig(body, c.path...); got != c.want {
			t.Errorf("%s = %v, want %v", strings.Join(c.path, "."), got, c.want)
		}
	}
	for _, p := range [][]string{{"dns", "tsig_secret"}, {"state", "secret_key"}, {"api_token"}} {
		if s, _ := dig(body, p...).(string); s == "" {
			t.Errorf("%s missing from the create response", strings.Join(p, "."))
		}
	}
}

func TestGetAndListNeverCarrySecrets(t *testing.T) {
	h, _, _ := tenantServer(t)
	_, created := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`)
	secrets := []string{dig(created, "dns", "tsig_secret").(string), dig(created, "state", "secret_key").(string), created["api_token"].(string)}

	for _, path := range []string{"/v1/tenants/tdemo", "/v1/tenants"} {
		rec, _ := call(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		for _, s := range secrets {
			if bytes.Contains(rec.Body.Bytes(), []byte(s)) {
				t.Errorf("GET %s leaks a secret", path)
			}
		}
	}
}

func TestRestoreThroughTheAPI(t *testing.T) {
	h, st, _ := tenantServer(t)
	st.Put(tenant.Record{Name: "grooveiq", Index: 4, Status: tenant.StatusReady})
	tokens, _ := tenant.NewTokens(tenanttest.TokenKey)
	tok, _ := tokens.Issue("tdemo")
	body := `{"name":"tdemo","index":4,"tsig_secret":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","state_secret":"state-secret-from-state","api_token":"` + tok + `"}`
	rec, out := call(t, h, http.MethodPost, "/v1/tenants", body)
	if rec.Code != http.StatusCreated || out["outcome"] != "reissued" || out["index"] == float64(4) {
		t.Fatalf("got %d %v, want 201 reissued on a new index", rec.Code, out)
	}
	if dig(out, "state", "secret_key") != "state-secret-from-state" {
		t.Error("a restore must hand back the secrets it was given")
	}
}

func TestTenantErrorMapping(t *testing.T) {
	h, _, b := tenantServer(t)

	if rec, _ := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"TOO_LONG_NAME"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid name: %d, want 400", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo","extra":1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d, want 400", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodGet, "/v1/tenants/nobody", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing tenant: %d, want 404", rec.Code)
	}

	b.FailState = errors.New("dial tcp 10.20.25.20:9000: connection refused")
	rec, out := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`)
	if rec.Code != http.StatusBadGateway || dig(out, "tenant", "status") != "provisioning" {
		t.Fatalf("failed step: %d %v, want 502 with the provisioning tenant", rec.Code, out)
	}
	if strings.Contains(rec.Body.String(), "10.20.25.20") {
		t.Errorf("502 body leaks the backend error: %s", rec.Body.String())
	}

	b.FailState = nil
	if rec, out := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusOK || out["outcome"] != "resumed" {
		t.Fatalf("resume: %d %v, want 200 resumed", rec.Code, out)
	}
	if rec, _ := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusConflict {
		t.Errorf("second create: %d, want 409", rec.Code)
	}

	b.FabricClaims = []tenant.Claim{{Index: 1, Zone: "tdemo"}}
	if rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/tdemo", ""); rec.Code != http.StatusConflict {
		t.Errorf("delete with the zone on the fabric: %d, want 409", rec.Code)
	}
	b.FabricClaims = nil
	if rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/tdemo", ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d, want 204", rec.Code)
	}
}

func TestReconcileAndEgress(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	b.DNSTenants = map[string]tenant.DNSTenant{} // PowerDNS was rebuilt

	rec, out := call(t, h, http.MethodPost, "/v1/tenants/eds/reconcile", "")
	if rec.Code != http.StatusOK || out["outcome"] != "reconciled" {
		t.Fatalf("reconcile: %d %v", rec.Code, out)
	}
	if _, ok := b.DNSTenants["eds"]; !ok {
		t.Error("reconcile did not re-ensure DNS")
	}
	if dig(out, "dns", "tsig_secret") != nil {
		t.Error("reconcile must not return secrets")
	}

	rec, out = call(t, h, http.MethodGet, "/v1/fabric/egress", "")
	vrfs, _ := out["vrfs"].([]any)
	if rec.Code != http.StatusOK || len(vrfs) != 1 || dig(vrfs[0].(map[string]any), "vrf") != "vrf_eds" {
		t.Fatalf("egress: %d %v", rec.Code, out)
	}
}

func TestUnconfiguredTenantsStillAnswer501(t *testing.T) {
	h := newTestServer(fakeDB{})
	rec, body := do(t, h, http.MethodGet, "/v1/tenants", "s3cret")
	if rec.Code != http.StatusNotImplemented || body["error"] != "not implemented" {
		t.Fatalf("got %d %v, want 501 without a tenant service", rec.Code, body)
	}
}

func TestEnrollmentCreatesTheAdmittedTenantOnce(t *testing.T) {
	h, _, _ := tenantServer(t)

	rec, adm := call(t, h, http.MethodPost, "/v1/admissions", `{"name":"tdemo"}`)
	if rec.Code != http.StatusCreated || adm["enrollment_token"] == "" {
		t.Fatalf("admit: %d %v", rec.Code, adm)
	}
	enroll := adm["enrollment_token"].(string)

	// The enrollment token is good for creating its own name, nothing else.
	if rec, _ := callAs(t, h, enroll, http.MethodGet, "/v1/tenants", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("list with an enrollment token: %d, want 401", rec.Code)
	}
	rec, created := callAs(t, h, enroll, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with the enrollment token: %d %v", rec.Code, created)
	}
	if rec, _ := callAs(t, h, enroll, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("reusing the enrollment token: %d, want 401", rec.Code)
	}

	// The tenant token it received reads its own tenant, and nothing else.
	tok := created["api_token"].(string)
	if rec, _ := callAs(t, h, tok, http.MethodGet, "/v1/tenants/tdemo", ""); rec.Code != http.StatusOK {
		t.Errorf("tenant reads itself: %d", rec.Code)
	}
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	if rec, _ := callAs(t, h, tok, http.MethodGet, "/v1/tenants/eds", ""); rec.Code != http.StatusNotFound {
		t.Errorf("tenant reads another tenant: %d, want 404", rec.Code)
	}
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/tenants", ""},
		{http.MethodPost, "/v1/admissions", `{"name":"x"}`},
		{http.MethodGet, "/v1/fabric/egress", ""},
		{http.MethodPost, "/v1/tenants/tdemo/reconcile", ""},
	} {
		if rec, _ := callAs(t, h, tok, r.method, r.path, r.body); rec.Code != http.StatusForbidden {
			t.Errorf("tenant %s %s: %d, want 403", r.method, r.path, rec.Code)
		}
	}
	if rec, _ := callAs(t, h, tok, http.MethodPost, "/v1/tenants", `{"name":"eds"}`); rec.Code != http.StatusForbidden {
		t.Errorf("tenant creating another name: %d, want 403", rec.Code)
	}
}

func TestEnrollmentTokenForAnotherNameIsRefusedAndSpent(t *testing.T) {
	h, _, _ := tenantServer(t)
	_, adm := call(t, h, http.MethodPost, "/v1/admissions", `{"name":"tdemo"}`)
	enroll := adm["enrollment_token"].(string)
	if rec, _ := callAs(t, h, enroll, http.MethodPost, "/v1/tenants", `{"name":"eds"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("create another name: %d, want 401", rec.Code)
	}
	if rec, _ := callAs(t, h, enroll, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after a mismatch the token is spent: %d, want 401", rec.Code)
	}
}

func TestTenantRestoresItselfAfterTheRegistryIsLost(t *testing.T) {
	h, _, _ := tenantServer(t)
	_, first := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`)
	tok := first["api_token"].(string)
	restore := `{"name":"tdemo","index":1,"tsig_secret":"` + dig(first, "dns", "tsig_secret").(string) +
		`","state_secret":"` + dig(first, "state", "secret_key").(string) + `","api_token":"` + tok + `"}`

	// A fresh API: same token key, empty registry.
	h2, _, _ := tenantServer(t)
	rec, out := callAs(t, h2, tok, http.MethodPost, "/v1/tenants", restore)
	if rec.Code != http.StatusCreated || out["outcome"] != "restored" {
		t.Fatalf("restore with its own token: %d %v", rec.Code, out)
	}
	if rec, _ := callAs(t, h2, tok, http.MethodGet, "/v1/tenants/tdemo", ""); rec.Code != http.StatusOK {
		t.Errorf("the restored token reads its tenant: %d", rec.Code)
	}
	if rec, _ := callAs(t, h2, "dvt1.tdemo.forged.mac", http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("a forged tenant token: %d, want 401", rec.Code)
	}
}

func TestAdmissionsWithoutEnrollment(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Enroller = nil
	svc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	h := New(Config{Token: "s3cret", DB: fakeDB{}, Logger: svc.Logger, Tenants: svc})
	if rec, _ := call(t, h, http.MethodPost, "/v1/admissions", `{"name":"tdemo"}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("admit without enrollment: %d, want 501", rec.Code)
	}
	if rec, _ := callAs(t, h, "anything", http.MethodPost, "/v1/tenants", `{"name":"tdemo"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token without enrollment: %d, want 401", rec.Code)
	}
}
