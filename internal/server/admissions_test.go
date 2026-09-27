package server

import (
	"net/http"
	"testing"
)

// The admission hands over the tenant developer network key with the token
// (ADR-0029 §1), and only the operator may admit or revoke.
func TestAdmissionReturnsTheDevKeyAndOnlyTheOperatorRevokes(t *testing.T) {
	h, _, b := tenantServer(t)

	rec, adm := call(t, h, http.MethodPost, "/v1/admissions", `{"name":"tdemo","mac":"AA-BB-CC-00-11-22"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admit: %d %v", rec.Code, adm)
	}
	wifi, _ := adm["wifi"].(map[string]any)
	if wifi["ssid"] != "DVNTM-TD" || wifi["psk"] == "" || wifi["psk"] == nil || wifi["mac"] != "aa:bb:cc:00:11:22" {
		t.Fatalf("wifi = %v", adm["wifi"])
	}

	// An enrollment token is not the operator.
	enroll := adm["enrollment_token"].(string)
	if rec, _ := callAs(t, h, enroll, http.MethodDelete, "/v1/admissions/tdemo", ""); rec.Code == http.StatusNoContent {
		t.Error("the enrollment token revoked its own admission")
	}
	if rec, _ := call(t, h, http.MethodDelete, "/v1/admissions/tdemo", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if _, ok := b.WiFiKeys["DVNTM-TD/tdemo-admission"]; ok {
		t.Error("the revoked key is still in the controller")
	}
	if rec, _ := call(t, h, http.MethodDelete, "/v1/admissions/tdemo", ""); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d, want 404", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodPost, "/v1/admissions", `{"name":"eds","mac":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("a bad mac: %d, want 400", rec.Code)
	}
}
