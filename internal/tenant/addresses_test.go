package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

const (
	macA = "aa:bb:cc:00:00:01"
	macB = "aa:bb:cc:00:00:02"
)

// device registers one with a MAC, which is what an address is reserved for.
func device(t *testing.T, svc *tenant.Service, tenantName, name, mac string) {
	t.Helper()
	if _, err := svc.CreateDevice(context.Background(), tenantName,
		tenant.DeviceRequest{Name: name, TrustClass: "iot", MAC: mac}); err != nil {
		t.Fatal(err)
	}
}

func TestAddressIsTheLowestFreeAndIsReservedAndNamed(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)

	a, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != "10.20.30.25" {
		t.Errorf("address = %s, want the first of the tenant range", a.Address)
	}
	if a.Status != tenant.StatusReady || a.MAC != macA {
		t.Errorf("address = %+v", a)
	}
	if a.FQDN != "stand-1.eds.mobile.deevnet.net" {
		t.Errorf("fqdn = %s", a.FQDN)
	}
	r, ok := b.Reservations["Deevnet API - eds/stand-1"]
	if !ok {
		t.Fatalf("no reservation on the DHCP server: %v", b.Reservations)
	}
	if r.Subnet != "10.20.30.0/24" || r.Address != "10.20.30.25" || r.MAC != macA || r.Hostname != "eds-stand-1" {
		t.Errorf("reservation = %+v", r)
	}
	// The name is the tenant's, in its own zone, and claims no PTR: the reverse
	// zone for the device network is the substrate's.
	rec, ok := b.DNSRecords["stand-1.eds.mobile.deevnet.net"]
	if !ok || rec.Address != "10.20.30.25" || rec.Reverse {
		t.Errorf("published record = %+v (present %v)", rec, ok)
	}
}

func TestSecondDeviceGetsTheNextAddressAcrossTenants(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	device(t, svc, "tdemo", "probe", macB)

	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}
	a, err := svc.CreateDeviceAddress(ctx, "tdemo", "probe", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != "10.20.30.26" {
		t.Errorf("address = %s, want .26: the range is shared, so another tenant's .25 is taken", a.Address)
	}
}

// Re-applying is how a restore converges, and must never move a device.
func TestReapplyingKeepsTheAddress(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	device(t, svc, "eds", "stand-2", macB)
	first, err := svc.CreateDeviceAddress(ctx, "eds", "stand-2", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}
	for _, requested := range []string{"", first.Address} {
		again, err := svc.CreateDeviceAddress(ctx, "eds", "stand-2", requested)
		if err != nil {
			t.Fatal(err)
		}
		if again.Address != first.Address {
			t.Errorf("re-apply with %q moved the device from %s to %s", requested, first.Address, again.Address)
		}
	}
}

// The restore path: the tenant's state remembers the address and asks for it.
func TestARequestedAddressIsGivenWhenFree(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	device(t, svc, "eds", "stand-1", macA)
	a, err := svc.CreateDeviceAddress(context.Background(), "eds", "stand-1", "10.20.30.50")
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != "10.20.30.50" {
		t.Errorf("address = %s, want the one asked for", a.Address)
	}
}

func TestRefusals(t *testing.T) {
	ctx := context.Background()
	var inv *tenant.InvalidError

	t.Run("outside the tenant range", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		ready(t, svc, "eds")
		device(t, svc, "eds", "stand-1", macA)
		// The gateway, a Pi lab host, the dynamic pool, another network, junk.
		for _, addr := range []string{"10.20.30.1", "10.20.30.11", "10.20.30.201", "10.20.99.25", "nonsense"} {
			if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", addr); !errors.As(err, &inv) {
				t.Errorf("%s: err = %v, want InvalidError", addr, err)
			}
		}
	})
	t.Run("a device with no mac", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		ready(t, svc, "eds")
		device(t, svc, "eds", "stand-1", "")
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); !errors.As(err, &inv) {
			t.Errorf("err = %v, want InvalidError", err)
		}
	})
	t.Run("an unregistered device", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		ready(t, svc, "eds")
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "ghost", ""); !errors.As(err, &inv) {
			t.Errorf("err = %v, want InvalidError", err)
		}
	})
	t.Run("a class with no range", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		ready(t, svc, "eds")
		if _, err := svc.CreateDevice(ctx, "eds", tenant.DeviceRequest{Name: "cam", TrustClass: "iot_vendor", MAC: macA}); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "cam", ""); !errors.As(err, &inv) {
			t.Errorf("err = %v, want InvalidError", err)
		}
	})
	t.Run("a site that reserves none", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		svc.Reservations = nil
		ready(t, svc, "eds")
		device(t, svc, "eds", "stand-1", macA)
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); !errors.As(err, &inv) {
			t.Errorf("err = %v, want InvalidError", err)
		}
	})
	t.Run("moving an address in place", func(t *testing.T) {
		svc, _, _ := tenanttest.NewService()
		ready(t, svc, "eds")
		device(t, svc, "eds", "stand-1", macA)
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "10.20.30.99"); !errors.As(err, &inv) {
			t.Errorf("err = %v, want InvalidError", err)
		}
	})
}

// The network is shared, so a clash is with another tenant as often as not, and
// the answer must not say who holds what.
func TestAClashNamesNobody(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}

	// The same MAC, registered by another tenant: allowed in the registry, which
	// enforces nothing, and refused here.
	device(t, svc, "tdemo", "copy", macA)
	_, err := svc.CreateDeviceAddress(ctx, "tdemo", "copy", "")
	if !errors.Is(err, tenant.ErrAddressConflict) {
		t.Fatalf("same MAC: err = %v, want ErrAddressConflict", err)
	}
	// The address another tenant holds.
	device(t, svc, "tdemo", "probe", macB)
	_, err2 := svc.CreateDeviceAddress(ctx, "tdemo", "probe", "10.20.30.25")
	if !errors.Is(err2, tenant.ErrAddressConflict) {
		t.Fatalf("same address: err = %v, want ErrAddressConflict", err2)
	}
	for _, e := range []error{err, err2} {
		if strings.Contains(e.Error(), "eds") || strings.Contains(e.Error(), "stand-1") {
			t.Errorf("the refusal names the holder: %q", e)
		}
	}
}

// A MAC or address the DHCP server already holds for a substrate host is
// refused, and leaves no half-made row to retry into the same wall.
func TestASubstrateHostsMACIsRefusedAndLeavesNoRow(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "pi", macA)
	b.Foreign[macA] = true

	if _, err := svc.CreateDeviceAddress(ctx, "eds", "pi", ""); !errors.Is(err, tenant.ErrAddressConflict) {
		t.Fatalf("err = %v, want ErrAddressConflict", err)
	}
	if _, err := st.GetDeviceAddress(ctx, "eds", "pi"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a row was left behind: %v", err)
	}
	if _, ok := b.DNSRecords["pi.eds.mobile.deevnet.net"]; ok {
		t.Error("a name was published for an address that was never reserved")
	}
}

func TestOneTenantCannotTakeTheWholeRange(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Site.AddressesPerTenant = 2
	ready(t, svc, "eds")
	ctx := context.Background()
	for i, mac := range []string{macA, macB} {
		name := []string{"one", "two"}[i]
		device(t, svc, "eds", name, mac)
		if _, err := svc.CreateDeviceAddress(ctx, "eds", name, ""); err != nil {
			t.Fatal(err)
		}
	}
	device(t, svc, "eds", "three", "aa:bb:cc:00:00:03")
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "three", ""); !errors.Is(err, tenant.ErrAddressQuota) {
		t.Errorf("err = %v, want ErrAddressQuota", err)
	}
}

// A DHCP server that will not take the write leaves the row behind, so a retry
// resumes with the same address.
func TestServerFailureLeavesAResumableRow(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	b.FailReservation = errors.New("router says no")

	a, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepAddress {
		t.Fatalf("err = %v, want a device-address step error", err)
	}
	if a.Address == "" {
		t.Error("the partial object must carry the address")
	}
	stored, err := st.GetDeviceAddress(ctx, "eds", "stand-1")
	if err != nil || stored.Status != tenant.StatusProvisioning {
		t.Fatalf("stored = %+v, %v; want a provisioning row", stored, err)
	}

	b.FailReservation = nil
	again, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Address != a.Address || again.Status != tenant.StatusReady {
		t.Errorf("retry = %+v, want %s ready", again, a.Address)
	}
}

// Swapping the hardware behind a name keeps the address, which is the point of
// asking for a fixed one.
func TestAChangedMACMovesTheReservation(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	a, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	if err != nil {
		t.Fatal(err)
	}
	device(t, svc, "eds", "stand-1", macB)

	r := b.Reservations["Deevnet API - eds/stand-1"]
	if r.MAC != macB || r.Address != a.Address {
		t.Errorf("reservation = %+v, want %s for the new MAC", r, a.Address)
	}
	got, err := svc.GetDeviceAddress(ctx, "eds", "stand-1")
	if err != nil || got.Status != tenant.StatusReady || got.MAC != macB {
		t.Errorf("address = %+v, %v", got, err)
	}
}

func TestAChangedMACIsRefusedWhenItClashesOrIsCleared(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	device(t, svc, "tdemo", "probe", macB)
	for _, x := range [][2]string{{"eds", "stand-1"}, {"tdemo", "probe"}} {
		if _, err := svc.CreateDeviceAddress(ctx, x[0], x[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.CreateDevice(ctx, "tdemo", tenant.DeviceRequest{Name: "probe", TrustClass: "iot", MAC: macA}); !errors.Is(err, tenant.ErrAddressConflict) {
		t.Errorf("taking another holder's MAC: err = %v, want ErrAddressConflict", err)
	}
	var inv *tenant.InvalidError
	if _, err := svc.CreateDevice(ctx, "tdemo", tenant.DeviceRequest{Name: "probe", TrustClass: "iot"}); !errors.As(err, &inv) {
		t.Errorf("clearing the MAC: err = %v, want InvalidError", err)
	}
	d, _ := svc.GetDevice(ctx, "tdemo", "probe")
	if d.MAC != macB {
		t.Errorf("a refused change was written: mac = %s", d.MAC)
	}
}

func TestDeleteGivesTheAddressBack(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}
	// A device holding an address is not deregistered from under it.
	var inv *tenant.InvalidError
	if err := svc.DeleteDevice(ctx, "eds", "stand-1"); !errors.As(err, &inv) {
		t.Fatalf("deleting the device first: err = %v, want InvalidError", err)
	}
	if err := svc.DeleteDeviceAddress(ctx, "eds", "stand-1"); err != nil {
		t.Fatal(err)
	}
	if len(b.Reservations) != 0 {
		t.Errorf("reservation left on the server: %v", b.Reservations)
	}
	if _, ok := b.DNSRecords["stand-1.eds.mobile.deevnet.net"]; ok {
		t.Error("the name is still published")
	}
	if _, err := st.GetDeviceAddress(ctx, "eds", "stand-1"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("row survived: %v", err)
	}
	if err := svc.DeleteDevice(ctx, "eds", "stand-1"); err != nil {
		t.Errorf("the device should now deregister: %v", err)
	}
}

func TestDeletingATenantRemovesItsReservations(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if len(b.Reservations) != 0 {
		t.Errorf("reservations orphaned on the server: %v", b.Reservations)
	}
}

// A rebuilt router has lost every reservation the API wrote, and inventory
// cannot put back what it does not hold.
func TestReconcilePutsReservationsBack(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	a, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	if err != nil {
		t.Fatal(err)
	}
	delete(b.Reservations, "Deevnet API - eds/stand-1")
	delete(b.DNSRecords, "stand-1.eds.mobile.deevnet.net")

	if _, err := svc.Reconcile(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if r := b.Reservations["Deevnet API - eds/stand-1"]; r.Address != a.Address || r.MAC != macA {
		t.Errorf("reservation after reconcile = %+v", r)
	}
	if _, ok := b.DNSRecords["stand-1.eds.mobile.deevnet.net"]; !ok {
		t.Error("the name was not republished")
	}
}

// The address is the substrate's and the name is the tenant's: a tenant may
// point further names at an address it holds, and at no other on that network.
func TestRecordsMayNameAReservedAddressOnly(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	device(t, svc, "eds", "stand-1", macA)
	a, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.PutRecord(ctx, "eds", "lights", a.Address); err != nil {
		t.Fatalf("a second name for the tenant's own device: %v", err)
	}
	var inv *tenant.InvalidError
	if err := svc.PutRecord(ctx, "tdemo", "lights", a.Address); !errors.As(err, &inv) {
		t.Errorf("another tenant's reserved address: err = %v, want InvalidError", err)
	}
	if err := svc.PutRecord(ctx, "eds", "other", "10.20.30.77"); !errors.As(err, &inv) {
		t.Errorf("an unreserved address: err = %v, want InvalidError", err)
	}
	// The address is not given back while a name still points at it.
	if err := svc.DeleteDeviceAddress(ctx, "eds", "stand-1"); !errors.As(err, &inv) {
		t.Errorf("delete with a record still pointing: err = %v, want InvalidError", err)
	}
	if err := svc.DeleteRecord(ctx, "eds", "lights"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteDeviceAddress(ctx, "eds", "stand-1"); err != nil {
		t.Errorf("delete once the record is gone: %v", err)
	}
}

// One name, one owner: a device's published name and a workload's or record's
// cannot be the same label in the tenant's zone.
func TestADeviceNameCannotShadowAnotherPublishedName(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	var inv *tenant.InvalidError

	if _, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "web"}); err != nil {
		t.Fatal(err)
	}
	device(t, svc, "eds", "web", macA)
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "web", ""); !errors.As(err, &inv) {
		t.Errorf("a device named like a workload: err = %v, want InvalidError", err)
	}

	device(t, svc, "eds", "stand-1", macB)
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "stand-1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "stand-1"}); !errors.As(err, &inv) {
		t.Errorf("a workload named like an addressed device: err = %v, want InvalidError", err)
	}
	if err := svc.PutRecord(ctx, "eds", "stand-1", "10.20.129.10"); !errors.As(err, &inv) {
		t.Errorf("a record named like an addressed device: err = %v, want InvalidError", err)
	}
}

func TestTheRangeRunsOut(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	r := svc.Site.AddressRanges["iot"]
	r.Last = r.First.Next()
	svc.Site.AddressRanges["iot"] = r
	ready(t, svc, "eds")
	ctx := context.Background()
	for i, mac := range []string{macA, macB} {
		name := []string{"one", "two"}[i]
		device(t, svc, "eds", name, mac)
		if _, err := svc.CreateDeviceAddress(ctx, "eds", name, ""); err != nil {
			t.Fatal(err)
		}
	}
	device(t, svc, "eds", "three", "aa:bb:cc:00:00:03")
	if _, err := svc.CreateDeviceAddress(ctx, "eds", "three", ""); !errors.Is(err, tenant.ErrAddressesExhausted) {
		t.Errorf("err = %v, want ErrAddressesExhausted", err)
	}
}
