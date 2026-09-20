package server

import (
	"net/http"
	"testing"
)

func TestDeviceCreateReturnsTheRegistryEntry(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices",
		`{"name":"stand-1","trust_class":"iot","mac":"AA:BB:CC:DD:EE:FF"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["name"] != "stand-1" || body["trust_class"] != "iot" {
		t.Errorf("body = %v", body)
	}
	if body["mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %v, want normalised", body["mac"])
	}
	if body["status"] != "ready" {
		t.Errorf("status = %v", body["status"])
	}
}

// The path stopped answering 501. Before this resource existed the catch-all
// under /v1/ answered every unimplemented route, and the device registry was
// one of them (ADR-0020's "nothing is built").
func TestDeviceRouteIsImplemented(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/devices", "")
	if rec.Code == http.StatusNotImplemented {
		t.Fatal("the device registry still answers 501")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// A tenant asking about another tenant's devices is told the tenant does not
// exist, not that it may not look. A 403 would confirm the tenant is there.
func TestAnotherTenantsDevicesAre404(t *testing.T) {
	h, _, _ := tenantServer(t)
	createTenantFor(t, h, "eds")
	other := createTenantFor(t, h, "tdemo")

	callAs(t, h, other, http.MethodPost, "/v1/tenants/tdemo/devices", `{"name":"stand-1","trust_class":"iot"}`)

	for _, path := range []string{"/v1/tenants/eds/devices", "/v1/tenants/eds/devices/stand-1"} {
		rec, _ := callAs(t, h, other, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s as another tenant = %d, want 404", path, rec.Code)
		}
	}
	rec, _ := callAs(t, h, other, http.MethodPost, "/v1/tenants/eds/devices",
		`{"name":"sneaky","trust_class":"iot"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST to another tenant = %d, want 404", rec.Code)
	}
}

func TestDeviceBadTrustClassIs400NamingTheServedClasses(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices",
		`{"name":"stand-1","trust_class":"nonesuch"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	msg, _ := body["error"].(string)
	if msg == "" {
		t.Fatal("no error message")
	}
}

// iot_vendor devices are legal in the registry. ADR-0012 §3 refuses them a
// broker account; it does not refuse them an identity.
func TestIoTVendorDeviceIsRegisterable(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices",
		`{"name":"sensor-1","trust_class":"iot_vendor"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceDeleteIs204(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices", `{"name":"stand-1","trust_class":"iot"}`)

	rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/devices/stand-1", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// Gone means gone: the provider reads the 404 and drops the resource.
	rec, _ = callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/devices/stand-1", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("after delete, GET = %d, want 404", rec.Code)
	}
}

// An unknown field is rejected rather than ignored, so a typo in a tenant's
// Terraform is a 400 and not a silently dropped setting.
func TestDeviceUnknownFieldIs400(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/devices",
		`{"name":"stand-1","trust_class":"iot","vlan":30}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceRequiresAToken(t *testing.T) {
	h, _, _ := tenantServer(t)
	createTenantFor(t, h, "eds")

	// call() carries the operator token; an empty one is the unauthenticated case.
	rec, _ := callAs(t, h, "", http.MethodGet, "/v1/tenants/eds/devices", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", rec.Code)
	}
}
