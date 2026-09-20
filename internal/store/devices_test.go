package store

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func seedTenantFor(t *testing.T, p *Postgres, name string) {
	t.Helper()
	if _, err := p.Create(context.Background(), name,
		tenant.Secrets{TSIG: "t", State: "s", APITokenHash: []byte{1}}, lowest); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRoundTrip(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	d, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot",
		MAC: "aa:bb:cc:dd:ee:ff", Status: tenant.StatusReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.MAC != "aa:bb:cc:dd:ee:ff" || d.Status != tenant.StatusReady {
		t.Fatalf("put returned %+v", d)
	}
	if d.CreatedAt.IsZero() || d.UpdatedAt.IsZero() {
		t.Error("timestamps not populated")
	}

	got, err := p.GetDevice(ctx, "eds", "stand-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != d.Name || got.TrustClass != "iot" || got.MAC != d.MAC {
		t.Errorf("get returned %+v", got)
	}
}

// A device with no MAC stores NULL and reads back as the empty string, so
// "no MAC recorded" is one value rather than two.
func TestDeviceWithoutMACReadsBackEmpty(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	if _, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot", Status: tenant.StatusReady,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetDevice(ctx, "eds", "stand-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MAC != "" {
		t.Errorf("mac = %q, want empty", got.MAC)
	}
}

// PutDevice upserts: the MAC and status move, the trust class and created_at
// do not.
func TestPutDeviceUpsertsWithoutMovingTheTrustClass(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	first, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot", Status: tenant.StatusReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot",
		MAC: "aa:bb:cc:dd:ee:ff", Status: tenant.StatusReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q", second.MAC)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("created_at moved on upsert")
	}
	list, err := p.ListDevices(ctx, "eds")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v (%d), %v", list, len(list), err)
	}
}

// A device for a tenant the registry does not hold is a missing tenant the
// caller can act on, not a foreign-key violation it cannot.
func TestPutDeviceForUnknownTenantIsNotFound(t *testing.T) {
	p := testStore(t)

	_, err := p.PutDevice(context.Background(), tenant.Device{
		Tenant: "nosuch", Name: "stand-1", TrustClass: "iot", Status: tenant.StatusReady,
	})
	if !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// Two tenants may hold the same MAC: there is no UNIQUE on the column, because
// a conflict would disclose another tenant's device (ADR-0020 §2).
func TestDeviceMACIsNotUniqueAcrossTenants(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedTenantFor(t, p, "tdemo")

	for _, name := range []string{"eds", "tdemo"} {
		if _, err := p.PutDevice(ctx, tenant.Device{
			Tenant: name, Name: "stand-1", TrustClass: "iot",
			MAC: "aa:bb:cc:dd:ee:ff", Status: tenant.StatusReady,
		}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestDeleteDeviceConverges(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	if _, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot", Status: tenant.StatusReady,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := p.DeleteDevice(ctx, "eds", "stand-1"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if _, err := p.GetDevice(ctx, "eds", "stand-1"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

// Deleting a tenant takes its devices with it: a device row holds nothing the
// substrate must tear down, unlike a workload, which is a real VM.
func TestDeletingATenantCascadesToDevices(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	if _, err := p.PutDevice(ctx, tenant.Device{
		Tenant: "eds", Name: "stand-1", TrustClass: "iot", Status: tenant.StatusReady,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListDevices(ctx, "eds")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("devices survived the tenant: %v", list)
	}
}
