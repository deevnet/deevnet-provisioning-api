package server

import (
	"net/http"
	"testing"
)

// The dashboard block names the server, the tenant's organisation and its
// login for everyone who can read the tenant; the password only when issued.
func TestCreateReturnsTheDashboardLoginAndReconcileReturnsItAgain(t *testing.T) {
	h, _, b := tenantServer(t)

	rec, out := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, out)
	}
	pw, _ := dig(out, "dashboard", "password").(string)
	if len(pw) != 48 {
		t.Fatalf("create returned dashboard password %q", pw)
	}
	if u := dig(out, "dashboard", "username"); u != "eds" {
		t.Errorf("username = %v, want the tenant's name", u)
	}
	if org, _ := dig(out, "dashboard", "org_id").(float64); int(org) != b.DashOrgs["eds"] {
		t.Errorf("org_id = %v, the server gave %d", dig(out, "dashboard", "org_id"), b.DashOrgs["eds"])
	}
	if u := dig(out, "dashboard", "url"); u != "https://dv02obs001v01.mobile.deevnet.net:3000" {
		t.Errorf("url = %v", u)
	}

	_, out = call(t, h, http.MethodGet, "/v1/tenants/eds", "")
	if dig(out, "dashboard", "password") != nil {
		t.Error("a GET returned the dashboard password")
	}
	if dig(out, "dashboard", "username") != "eds" {
		t.Error("a GET dropped the dashboard login's name")
	}

	rec, out = call(t, h, http.MethodPost, "/v1/tenants/eds/reconcile", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reconcile: %d %v", rec.Code, out)
	}
	if got, _ := dig(out, "dashboard", "password").(string); got != pw {
		t.Errorf("reconcile returned password %q, want the one issued", got)
	}
}
