package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// ADR-0029 §1: a tenant developer needs the tenant developer network to reach
// the API, so admission hands over a key for it with the enrollment token.
func TestAdmissionIssuesATenantDevKey(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	adm, err := svc.Admit(context.Background(), "tdemo", "")
	if err != nil {
		t.Fatal(err)
	}
	if adm.WiFi == nil || adm.WiFi.SSID != "DVNTM-TD" || !tenant.ValidPSK(adm.WiFi.PSK) {
		t.Fatalf("wifi = %+v", adm.WiFi)
	}
	got, ok := b.WiFiKeys["DVNTM-TD/tdemo-admission"]
	if !ok || got.PSK != adm.WiFi.PSK || got.VLAN != 45 || got.MAC != "" {
		t.Fatalf("controller holds %+v (ok=%v)", got, ok)
	}
}

// Admitting again - an expired or lost admission - replaces the key, and the
// one handed over first stops working.
func TestReadmissionRotatesTheKey(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ctx := context.Background()
	first, _ := svc.Admit(ctx, "tdemo", "")
	second, err := svc.Admit(ctx, "tdemo", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.WiFi.PSK == second.WiFi.PSK {
		t.Fatal("a second admission reissued the same key")
	}
	if b.WiFiKeys["DVNTM-TD/tdemo-admission"].PSK != second.WiFi.PSK {
		t.Error("the controller still holds the first key")
	}
}

// ADR-0029 §3: an optional MAC binds the key to one laptop, in the form the
// controller documents.
func TestAdmissionBindsTheKeyToAMAC(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ctx := context.Background()
	adm, err := svc.Admit(ctx, "tdemo", "aa:bb:cc:00:11:22")
	if err != nil {
		t.Fatal(err)
	}
	if adm.WiFi.MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("reported mac = %q", adm.WiFi.MAC)
	}
	if got := b.WiFiKeys["DVNTM-TD/tdemo-admission"].MAC; got != "AA-BB-CC-00-11-22" {
		t.Errorf("controller mac = %q", got)
	}
	var inv *tenant.InvalidError
	if _, err := svc.Admit(ctx, "eds", "not-a-mac"); !errors.As(err, &inv) {
		t.Errorf("a bad mac: %v, want InvalidError", err)
	}
}

// Once the tenant exists the key is one of its own, "admission": listed,
// deletable, and revoked with the tenant.
func TestCreatingTheTenantAdoptsTheKeyAndDeletingItRevokesIt(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	adm, _ := svc.Admit(ctx, "tdemo", "aa:bb:cc:00:11:22")
	if err := svc.Redeem(ctx, adm.EnrollmentToken, "tdemo"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	k, err := svc.GetWiFiKey(ctx, "tdemo", tenant.AdmissionKeyName)
	if err != nil {
		t.Fatalf("the admission key is not the tenant's: %v", err)
	}
	if k.TrustClass != "tenant_dev" || k.PSK != adm.WiFi.PSK || k.MAC != "aa:bb:cc:00:11:22" || k.SSID != "DVNTM-TD" {
		t.Errorf("adopted key = %+v", k)
	}
	if _, err := st.GetAdmissionKey(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("the admission row survived adoption: %v", err)
	}

	if err := svc.Delete(ctx, "tdemo"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.WiFiKeys["DVNTM-TD/tdemo-admission"]; ok {
		t.Error("the tenant is gone and its developer key still works")
	}
}

// A tenant may issue itself more developer keys, one per laptop, like any
// other trust class (ADR-0029 §2).
func TestATenantIssuesItselfMoreDevKeys(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	k, err := svc.CreateWiFiKey(context.Background(), "eds",
		tenant.WiFiKeyRequest{Name: "alex-laptop", TrustClass: "tenant_dev", MAC: "AA-BB-CC-DD-EE-01"})
	if err != nil {
		t.Fatal(err)
	}
	if k.SSID != "DVNTM-TD" || k.VLAN != 45 {
		t.Errorf("key = %+v", k)
	}
	if got := b.WiFiKeys["DVNTM-TD/eds-alex-laptop"].MAC; got != "AA-BB-CC-DD-EE-01" {
		t.Errorf("controller mac = %q", got)
	}
}

// The operator withdraws an admission that was never used.
func TestRevokingAnUnusedAdmission(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Admit(ctx, "tdemo", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeAdmission(ctx, "tdemo"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.WiFiKeys["DVNTM-TD/tdemo-admission"]; ok {
		t.Error("the revoked key still works")
	}
	if _, err := st.GetAdmissionKey(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("row survived: %v", err)
	}
	if err := svc.RevokeAdmission(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a second revoke: %v, want ErrNotFound", err)
	}
}

// A site that issues no admission key admits exactly as before.
func TestNoAdmissionClassIssuesNoKey(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	svc.Site.AdmissionClass = ""
	adm, err := svc.Admit(context.Background(), "tdemo", "")
	if err != nil {
		t.Fatal(err)
	}
	if adm.WiFi != nil || len(b.WiFiKeys) != 0 {
		t.Errorf("wifi = %+v, controller %v", adm.WiFi, b.WiFiKeys)
	}
}
