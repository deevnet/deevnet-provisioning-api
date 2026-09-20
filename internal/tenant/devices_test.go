package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func TestDeviceRegisteredInItsTrustClass(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")

	d, err := svc.CreateDevice(context.Background(), "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Tenant != "eds" || d.Name != "stand-1" || d.TrustClass != "iot" {
		t.Errorf("device = %+v", d)
	}
	// A device calls no backend, so it is ready the moment its row exists.
	// There is no provisioning state to resume.
	if d.Status != tenant.StatusReady {
		t.Errorf("status = %s, want ready", d.Status)
	}
	if d.MAC != "" {
		t.Errorf("mac = %q, want empty when none was supplied", d.MAC)
	}
}

// A device registry needs no wireless controller: it records the tenant's own
// estate rather than writing anything to the air. A site with no Wireless
// backend still registers devices, which is what makes this buildable ahead of
// the broker and of any device-facing service (ADR-0020's order of work).
func TestDeviceNeedsNoWirelessBackend(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Wireless = nil
	ready(t, svc, "eds")

	if _, err := svc.CreateDevice(context.Background(), "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"}); err != nil {
		t.Fatalf("registering a device without a wireless backend: %v", err)
	}
}

func TestDeviceTrustClassMustBeServed(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")

	_, err := svc.CreateDevice(context.Background(), "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "nonesuch"})
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want InvalidError", err)
	}
	// The message has to say what the tenant may ask for instead.
	if !strings.Contains(err.Error(), "iot") {
		t.Errorf("error does not name the served classes: %v", err)
	}
}

func TestDeviceNameIsADNSLabel(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	for _, name := range []string{"", "Stand", "1stand", "stand_1", "stand-", strings.Repeat("s", 21)} {
		_, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: name, TrustClass: "iot"})
		var inv *tenant.InvalidError
		if !errors.As(err, &inv) {
			t.Errorf("name %q was accepted (err = %v)", name, err)
		}
	}
}

func TestDeviceMACIsNormalised(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	// The three spellings a tenant actually copies off a label or a console.
	for i, in := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabbccddeeff"} {
		name := []string{"stand-1", "stand-2", "stand-3"}[i]
		d, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: name, TrustClass: "iot", MAC: in})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if d.MAC != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("%q normalised to %q", in, d.MAC)
		}
	}

	for _, bad := range []string{"aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:gg", "not-a-mac", "aabbccddeeff00"} {
		_, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: "stand-9", TrustClass: "iot", MAC: bad})
		var inv *tenant.InvalidError
		if !errors.As(err, &inv) {
			t.Errorf("mac %q was accepted (err = %v)", bad, err)
		}
	}
}

// Two tenants may record the same MAC. It is a label for the owner, never an
// authorization input (ADR-0020 §2), so there is nothing for the substrate to
// arbitrate - and refusing the second would disclose that another tenant holds
// it, which is what the API's scoping exists to prevent.
func TestTwoTenantsMayRecordTheSameMAC(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	req := tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot", MAC: "aa:bb:cc:dd:ee:ff"}

	if _, err := svc.CreateDevice(ctx, "eds", req); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateDevice(ctx, "tdemo", req); err != nil {
		t.Fatalf("a second tenant could not record the same MAC: %v", err)
	}
}

// Re-applying an unchanged resource converges, and the MAC is the one field a
// tenant may correct in place: swapping the hardware behind a name is an
// inventory change, not a new device.
func TestReregisteringConvergesAndUpdatesTheMAC(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	first, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateDevice(ctx, "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot", MAC: "AA:BB:CC:DD:EE:FF"})
	if err != nil {
		t.Fatal(err)
	}
	if second.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q", second.MAC)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("re-applying replaced the device rather than updating it")
	}
	list, err := svc.ListDevices(ctx, "eds")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("re-applying made %d devices", len(list))
	}
}

// Moving a device between trust classes would change its SSID, its VLAN and any
// later service grants at once, under an unchanged name. The provider marks the
// field RequiresReplace; the rule is enforced here as well, because an API that
// relies on a client to enforce it does not enforce it.
func TestDeviceCannotChangeTrustClass(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	if _, err := svc.CreateDevice(ctx, "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.CreateDevice(ctx, "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot_vendor"})
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want InvalidError", err)
	}
}

func TestDeleteDeviceIsIdempotent(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	if _, err := svc.CreateDevice(ctx, "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteDevice(ctx, "eds", "stand-1"); err != nil {
		t.Fatal(err)
	}
	// A second delete finds nothing to delete and says so, which is what the
	// provider reads to stop.
	if err := svc.DeleteDevice(ctx, "eds", "stand-1"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
}

func TestDeviceRegistrationIsAudited(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	ready(t, svc, "eds")

	if _, err := svc.CreateDevice(context.Background(), "eds",
		tenant.DeviceRequest{Name: "stand-1", TrustClass: "iot"}); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range st.AuditLog {
		if e.Action == "device-create" && e.Tenant == "eds" {
			found = true
		}
	}
	if !found {
		t.Errorf("no device-create audit entry; log = %v", st.AuditLog)
	}
}
