package server

import (
	"net/http"
	"testing"
)

// The tenant is told which account its ssh_keys land on, so no page has to
// name it and a site can change it without the tenant guessing (ADR-0028).
func TestWorkloadNamesItsLoginUser(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/workloads",
		`{"name":"services","ssh_keys":["ssh-ed25519 AAAAC3Nz tenant@laptop"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["login_user"] == "" || body["login_user"] == nil {
		t.Errorf("no login_user in %v", body)
	}
	if body["fqdn"] != "services.eds.mobile.deevnet.net" {
		t.Errorf("fqdn = %v", body["fqdn"])
	}
}
