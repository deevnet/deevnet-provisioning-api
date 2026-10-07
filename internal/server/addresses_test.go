package server

import (
	"net/http"
	"strings"
	"testing"
)

func registerWithMAC(t *testing.T, h http.Handler, token, tenantName, device, mac string) {
	t.Helper()
	rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/"+tenantName+"/devices",
		`{"name":"`+device+`","trust_class":"iot","mac":"`+mac+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering %s: %d %s", device, rec.Code, rec.Body.String())
	}
}

func TestAddressCreateReturnsTheAddressAndTheName(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	registerWithMAC(t, h, token, "eds", "stand-1", "AA:BB:CC:00:00:01")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["address"] != "10.20.30.25" || body["mac"] != "aa:bb:cc:00:00:01" || body["status"] != "ready" {
		t.Errorf("body = %v", body)
	}
	if body["fqdn"] != "stand-1.eds.mobile.deevnet.net" {
		t.Errorf("fqdn = %v", body["fqdn"])
	}

	rec, body = callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/devices/stand-1/address", "")
	if rec.Code != http.StatusOK || body["address"] != "10.20.30.25" {
		t.Errorf("GET = %d %v", rec.Code, body)
	}
}

// What the provider's restore path depends on: no address is a 404, and a
// delete is a 204 followed by one.
func TestAddressAbsentIs404AndDeleteIs204(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	registerWithMAC(t, h, token, "eds", "stand-1", "aa:bb:cc:00:00:01")

	rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/devices/stand-1/address", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("before create, GET = %d, want 404", rec.Code)
	}
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{}`)
	rec, _ = callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/devices/stand-1/address", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/devices/stand-1/address", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("after delete, GET = %d, want 404", rec.Code)
	}
}

// A clash on a shared network is a 409 that says nothing about the holder.
func TestAddressClashIs409AndNamesNobody(t *testing.T) {
	h, _, _ := tenantServer(t)
	eds := createTenantFor(t, h, "eds")
	other := createTenantFor(t, h, "tdemo")
	registerWithMAC(t, h, eds, "eds", "stand-1", "aa:bb:cc:00:00:01")
	callAs(t, h, eds, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{}`)

	registerWithMAC(t, h, other, "tdemo", "copy", "aa:bb:cc:00:00:01")
	registerWithMAC(t, h, other, "tdemo", "probe", "aa:bb:cc:00:00:02")
	for path, payload := range map[string]string{
		"/v1/tenants/tdemo/devices/copy/address":  `{}`,
		"/v1/tenants/tdemo/devices/probe/address": `{"address":"10.20.30.25"}`,
	} {
		rec, _ := callAs(t, h, other, http.MethodPost, path, payload)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s = %d %s, want 409", path, rec.Code, rec.Body.String())
		}
		if s := rec.Body.String(); strings.Contains(s, "eds") || strings.Contains(s, "stand-1") {
			t.Errorf("the refusal names the holder: %s", s)
		}
	}
}

func TestAddressRefusalsAre400(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	registerWithMAC(t, h, token, "eds", "stand-1", "aa:bb:cc:00:00:01")
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices", `{"name":"nomac","trust_class":"iot"}`)

	for path, payload := range map[string]string{
		"/v1/tenants/eds/devices/stand-1/address": `{"address":"10.20.30.201"}`, // the dynamic pool
		"/v1/tenants/eds/devices/nomac/address":   `{}`,
		"/v1/tenants/eds/devices/ghost/address":   `{}`,
	} {
		rec, _ := callAs(t, h, token, http.MethodPost, path, payload)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s = %d %s, want 400", path, payload, rec.Code, rec.Body.String())
		}
	}
	// A typo in a tenant's Terraform is a 400, not a dropped setting.
	rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{"ip":"10.20.30.30"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field = %d, want 400", rec.Code)
	}
}

func TestAnotherTenantsAddressIs404(t *testing.T) {
	h, _, _ := tenantServer(t)
	eds := createTenantFor(t, h, "eds")
	other := createTenantFor(t, h, "tdemo")
	registerWithMAC(t, h, eds, "eds", "stand-1", "aa:bb:cc:00:00:01")
	callAs(t, h, eds, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{}`)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		rec, _ := callAs(t, h, other, method, "/v1/tenants/eds/devices/stand-1/address", `{}`)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s as another tenant = %d, want 404", method, rec.Code)
		}
	}
	rec, _ := callAs(t, h, "", http.MethodGet, "/v1/tenants/eds/devices/stand-1/address", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", rec.Code)
	}
}

// The router did not take the write: 502 with the address the row holds, and
// no backend detail in the body.
func TestAddressBackendFailureIs502WithTheAddress(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	registerWithMAC(t, h, token, "eds", "stand-1", "aa:bb:cc:00:00:01")
	b.FailReservation = errStr("dial tcp 10.20.25.1:443: connection refused")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices/stand-1/address", `{}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	partial, _ := body["address"].(map[string]any)
	if partial["address"] != "10.20.30.25" || partial["status"] != "provisioning" {
		t.Errorf("partial = %v", partial)
	}
	if strings.Contains(rec.Body.String(), "10.20.25.1") {
		t.Errorf("the body carries a backend address: %s", rec.Body.String())
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }
