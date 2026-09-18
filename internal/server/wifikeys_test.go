package server

import (
	"net/http"
	"strings"
	"testing"
)

// createTenant registers a tenant and returns its API token.
func createTenantFor(t *testing.T, h http.Handler, name string) string {
	t.Helper()
	rec, body := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"`+name+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", name, rec.Code, rec.Body.String())
	}
	tok, _ := body["api_token"].(string)
	if tok == "" {
		t.Fatalf("no api_token for %s", name)
	}
	return tok
}

func TestWiFiKeyCreateReturnsTheKeyAndTheSSID(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/wifi-keys",
		`{"name":"devices","trust_class":"iot"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["ssid"] != "DVNTM-IOT" || body["vlan"].(float64) != 30 {
		t.Errorf("ssid/vlan = %v/%v", body["ssid"], body["vlan"])
	}
	psk, _ := body["psk"].(string)
	if len(psk) != 32 {
		t.Errorf("psk = %q", psk)
	}
	if body["secrets_stored"] != true {
		t.Error("secrets_stored should be true on a fresh key")
	}
}

// A read says whether the key exists and whether the API's copy is intact. It
// does not hand the password back: the holder already has it, and returning it
// on every read widens exposure for nothing.
func TestWiFiKeyReadDoesNotReturnThePSK(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/wifi-keys", `{"name":"devices","trust_class":"iot"}`)

	rec, body := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/wifi-keys/devices", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, present := body["psk"]; present {
		t.Error("a read returned the psk")
	}
	if body["ssid"] != "DVNTM-IOT" {
		t.Errorf("ssid = %v", body["ssid"])
	}

	rec, list := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/wifi-keys", "")
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if strings.Contains(rec.Body.String(), "psk") {
		t.Errorf("the list leaked a psk field: %v", list)
	}
}

// Another tenant's key is 404, not 403: a token must not be able to find out
// which tenants hold keys.
func TestAnotherTenantsKeyIsNotFound(t *testing.T) {
	h, _, _ := tenantServer(t)
	edsToken := createTenantFor(t, h, "eds")
	tdemoToken := createTenantFor(t, h, "tdemo")
	callAs(t, h, edsToken, http.MethodPost, "/v1/tenants/eds/wifi-keys", `{"name":"devices","trust_class":"iot"}`)

	for _, path := range []string{"/v1/tenants/eds/wifi-keys", "/v1/tenants/eds/wifi-keys/devices"} {
		rec, _ := callAs(t, h, tdemoToken, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s as tdemo = %d, want 404", path, rec.Code)
		}
	}
	rec, _ := callAs(t, h, tdemoToken, http.MethodPost, "/v1/tenants/eds/wifi-keys",
		`{"name":"sneaky","trust_class":"iot"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST as tdemo = %d, want 404", rec.Code)
	}
}

func TestWiFiKeyDelete(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/wifi-keys", `{"name":"devices","trust_class":"iot"}`)

	rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/wifi-keys/devices", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(b.WiFiKeys) != 0 {
		t.Error("key still on the controller")
	}
}

func TestWiFiKeyUnknownTrustClassIsABadRequest(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/wifi-keys",
		`{"name":"devices","trust_class":"nope"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "iot") {
		t.Errorf("error should name the classes served: %v", body["error"])
	}
}
