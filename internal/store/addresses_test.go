package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func seedDevice(t *testing.T, p *Postgres, tenantName, name, mac string) {
	t.Helper()
	if _, err := p.PutDevice(context.Background(), tenant.Device{
		Tenant: tenantName, Name: name, TrustClass: "iot", MAC: mac, Status: tenant.StatusReady,
	}); err != nil {
		t.Fatal(err)
	}
}

// nextFree is the shape of the service's pick: the lowest of .25 upwards that
// nothing in held has taken.
func nextFree(held []tenant.DeviceAddress) (string, error) {
	taken := map[string]bool{}
	for _, h := range held {
		taken[h.Address] = true
	}
	for n := 25; n <= 200; n++ {
		if a := fmt.Sprintf("10.20.30.%d", n); !taken[a] {
			return a, nil
		}
	}
	return "", tenant.ErrAddressesExhausted
}

func address(tenantName, device string) tenant.DeviceAddress {
	return tenant.DeviceAddress{Tenant: tenantName, Device: device, TrustClass: "iot", Status: tenant.StatusProvisioning}
}

func TestAddressRoundTripReadsTheDevicesMAC(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:01")

	a, err := p.CreateDeviceAddress(ctx, address("eds", "stand-1"), nextFree)
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != "10.20.30.25" || a.MAC != "aa:bb:cc:00:00:01" || a.Status != tenant.StatusProvisioning {
		t.Fatalf("created %+v", a)
	}
	if err := p.SetDeviceAddressStatus(ctx, "eds", "stand-1", tenant.StatusReady); err != nil {
		t.Fatal(err)
	}
	// The MAC is not stored with the address: change the device's and the
	// address reports the new one.
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:02")
	got, err := p.GetDeviceAddress(ctx, "eds", "stand-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MAC != "aa:bb:cc:00:00:02" || got.Status != tenant.StatusReady || got.Address != "10.20.30.25" {
		t.Errorf("got %+v", got)
	}
}

// Re-applying keeps the address and does not consult pick, which is what
// stops a restore from moving a device.
func TestReapplyingAnAddressKeepsItAndDoesNotPick(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:01")
	first, err := p.CreateDeviceAddress(ctx, address("eds", "stand-1"), nextFree)
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.CreateDeviceAddress(ctx, address("eds", "stand-1"), func([]tenant.DeviceAddress) (string, error) {
		t.Error("pick was called for a device that already holds an address")
		return "10.20.30.99", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.Address != first.Address {
		t.Errorf("address moved from %s to %s", first.Address, again.Address)
	}
}

// pick sees every tenant's addresses in the class, with their MACs: that is
// what a clash check across tenants is made from.
func TestPickSeesOtherTenantsAddresses(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedTenantFor(t, p, "tdemo")
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:01")
	seedDevice(t, p, "tdemo", "probe", "aa:bb:cc:00:00:02")
	if _, err := p.CreateDeviceAddress(ctx, address("eds", "stand-1"), nextFree); err != nil {
		t.Fatal(err)
	}
	var seen []tenant.DeviceAddress
	a, err := p.CreateDeviceAddress(ctx, address("tdemo", "probe"), func(held []tenant.DeviceAddress) (string, error) {
		seen = held
		return nextFree(held)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Tenant != "eds" || seen[0].MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("pick saw %+v", seen)
	}
	if a.Address != "10.20.30.26" {
		t.Errorf("address = %s", a.Address)
	}
	all, err := p.ListClassAddresses(ctx, "iot")
	if err != nil || len(all) != 2 {
		t.Errorf("class list = %v, %v", all, err)
	}
	mine, err := p.ListDeviceAddresses(ctx, "tdemo")
	if err != nil || len(mine) != 1 || mine[0].Device != "probe" {
		t.Errorf("tenant list = %v, %v", mine, err)
	}
}

// Many devices asking at once each get their own address: the lock, not luck.
func TestConcurrentCreatesNeverShareAnAddress(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	const n = 12
	for i := 0; i < n; i++ {
		seedDevice(t, p, "eds", fmt.Sprintf("d%d", i), fmt.Sprintf("aa:bb:cc:00:01:%02x", i))
	}
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := p.CreateDeviceAddress(ctx, address("eds", fmt.Sprintf("d%d", i)), nextFree)
			got[i], errs[i] = a.Address, err
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("create %d: %v", i, errs[i])
		}
		if seen[got[i]] {
			t.Fatalf("address %s was given twice: %v", got[i], got)
		}
		seen[got[i]] = true
	}
}

func TestAnAddressNeedsItsDevice(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	if _, err := p.CreateDeviceAddress(ctx, address("eds", "ghost"), nextFree); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if _, err := p.GetDeviceAddress(ctx, "eds", "ghost"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("get: err = %v, want ErrNotFound", err)
	}
	if err := p.SetDeviceAddressStatus(ctx, "eds", "ghost", tenant.StatusReady); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("set status: err = %v, want ErrNotFound", err)
	}
}

// A refusal from pick writes nothing.
func TestARefusedPickLeavesNoRow(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:01")
	_, err := p.CreateDeviceAddress(ctx, address("eds", "stand-1"), func([]tenant.DeviceAddress) (string, error) {
		return "", tenant.ErrAddressConflict
	})
	if !errors.Is(err, tenant.ErrAddressConflict) {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.GetDeviceAddress(ctx, "eds", "stand-1"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a row was written: %v", err)
	}
}

func TestDeleteIsRepeatableAndATenantDeleteCascades(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedDevice(t, p, "eds", "stand-1", "aa:bb:cc:00:00:01")
	seedDevice(t, p, "eds", "stand-2", "aa:bb:cc:00:00:02")
	for _, d := range []string{"stand-1", "stand-2"} {
		if _, err := p.CreateDeviceAddress(ctx, address("eds", d), nextFree); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := p.DeleteDeviceAddress(ctx, "eds", "stand-1"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	// The freed address is the next one handed out.
	seedDevice(t, p, "eds", "stand-3", "aa:bb:cc:00:00:03")
	a, err := p.CreateDeviceAddress(ctx, address("eds", "stand-3"), nextFree)
	if err != nil || a.Address != "10.20.30.25" {
		t.Errorf("after a delete, next = %+v, %v; want .25 again", a, err)
	}
	if err := p.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	left, err := p.ListClassAddresses(ctx, "iot")
	if err != nil || len(left) != 0 {
		t.Errorf("addresses survived the tenant: %v, %v", left, err)
	}
}
