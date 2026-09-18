package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// ready registers a tenant the Wi-Fi tests can hang keys off.
func ready(t *testing.T, svc *tenant.Service, name string) {
	t.Helper()
	if _, err := svc.Create(context.Background(), tenant.CreateRequest{Name: name}); err != nil {
		t.Fatal(err)
	}
}

func TestWiFiKeyIssuedOnItsTrustClassVLAN(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")

	k, err := svc.CreateWiFiKey(context.Background(), "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	if k.SSID != "DVNTM-IOT" || k.VLAN != 30 {
		t.Errorf("key landed on %s/VLAN %d, want DVNTM-IOT/30", k.SSID, k.VLAN)
	}
	if !tenant.ValidPSK(k.PSK) {
		t.Errorf("generated psk %q is not one the controller would take", k.PSK)
	}
	if k.Status != tenant.StatusReady {
		t.Errorf("status = %s", k.Status)
	}
	// The controller holds it under "<tenant>-<name>", which is what keeps two
	// tenants' keys apart inside one shared profile.
	spec, ok := b.WiFiKeys["DVNTM-IOT/eds-devices"]
	if !ok {
		t.Fatalf("key not written to the controller; have %v", b.WiFiKeys)
	}
	if spec.VLAN != 30 || spec.PSK != k.PSK {
		t.Errorf("controller has %+v", spec)
	}
}

// Re-applying an unchanged resource must not mint a new key: every device
// flashed with the old one would fall off the air.
func TestReissuingKeepsTheSameKey(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	req := tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"}

	first, err := svc.CreateWiFiKey(ctx, "eds", req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateWiFiKey(ctx, "eds", req)
	if err != nil {
		t.Fatal(err)
	}
	if first.PSK != second.PSK {
		t.Error("re-applying minted a new psk; every flashed device would stop associating")
	}
}

// The restore path: the tenant holds the authoritative copy and puts it back,
// so the controller is made to match the devices (ADR-0012 §5).
func TestSuppliedKeyIsAdopted(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	const held = "theKeyTheDevicesWereFlashedWith"

	k, err := svc.CreateWiFiKey(context.Background(), "eds",
		tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot", PSK: held})
	if err != nil {
		t.Fatal(err)
	}
	if k.PSK != held {
		t.Errorf("psk = %q, want the supplied one", k.PSK)
	}
	if b.WiFiKeys["DVNTM-IOT/eds-devices"].PSK != held {
		t.Error("the controller was not made to match the devices")
	}
}

func TestSuppliedKeyMustBeOneTheControllerTakes(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	for _, bad := range []string{"short", strings.Repeat("x", 64), "has a space", "tab\there"} {
		_, err := svc.CreateWiFiKey(context.Background(), "eds",
			tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot", PSK: bad})
		var inv *tenant.InvalidError
		if !errors.As(err, &inv) {
			t.Errorf("psk %q was accepted (err %v)", bad, err)
		}
	}
}

func TestUnknownTrustClassIsRefusedBeforeAnyWrite(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")

	_, err := svc.CreateWiFiKey(context.Background(), "eds",
		tenant.WiFiKeyRequest{Name: "devices", TrustClass: "tenant_transit"})
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want invalid", err)
	}
	if !strings.Contains(err.Error(), "iot") {
		t.Errorf("the refusal should say what the site does serve: %v", err)
	}
	if len(b.WiFiKeys) != 0 {
		t.Error("nothing should have reached the controller")
	}
}

// A tenant never picks a VLAN, so a key cannot change class: every device
// already holding it would move VLAN silently.
func TestTrustClassCannotChange(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	if _, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot_vendor"})
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want invalid", err)
	}
}

// A controller that will not take the write leaves the row behind, so a retry
// resumes with the same key rather than issuing a second one.
func TestControllerFailureLeavesAResumableRow(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	b.FailWireless = errors.New("controller says no")

	k, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepWiFiKey {
		t.Fatalf("err = %v, want a wifi-key step error", err)
	}
	if k.PSK == "" {
		t.Error("the partial object must carry the psk, or a retry mints a second key")
	}
	stored, err := st.GetWiFiKey(ctx, "eds", "devices")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != tenant.StatusProvisioning {
		t.Errorf("status = %s, want provisioning", stored.Status)
	}

	b.FailWireless = nil
	again, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	if again.PSK != k.PSK {
		t.Error("the retry did not converge on the key already issued")
	}
	if again.Status != tenant.StatusReady {
		t.Errorf("status = %s", again.Status)
	}
}

func TestDeleteRevokesAtTheControllerAndInTheRegistry(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteWiFiKey(ctx, "eds", "devices"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.WiFiKeys["DVNTM-IOT/eds-devices"]; ok {
		t.Error("the key is still on the controller")
	}
	if _, err := st.GetWiFiKey(ctx, "eds", "devices"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("registry row survived: %v", err)
	}
}

// A key left behind when its tenant is deleted would belong to nobody and still
// let a device onto the IoT segment.
func TestDeletingATenantRevokesItsKeys(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if len(b.WiFiKeys) != 0 {
		t.Errorf("keys orphaned on the controller: %v", b.WiFiKeys)
	}
}

// A site with no wireless controller refuses with a reason.
func TestNoWirelessBackendRefuses(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Wireless = nil
	ready(t, svc, "eds")
	_, err := svc.CreateWiFiKey(context.Background(), "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want invalid", err)
	}
}

// Two tenants' keys sit in the same profile on the same SSID and VLAN. That is
// the model: the key is per tenant, the SSID and VLAN are the trust class's.
func TestTwoTenantsShareTheSSIDAndVLAN(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()

	a, err := svc.CreateWiFiKey(ctx, "eds", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := svc.CreateWiFiKey(ctx, "tdemo", tenant.WiFiKeyRequest{Name: "devices", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	if a.SSID != c.SSID || a.VLAN != c.VLAN {
		t.Error("tenants should share the trust class's SSID and VLAN")
	}
	if a.PSK == c.PSK {
		t.Fatal("tenants must not share a key")
	}
	if len(b.WiFiKeys) != 2 {
		t.Errorf("controller holds %d keys, want 2", len(b.WiFiKeys))
	}
}
