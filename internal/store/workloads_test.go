package store

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func TestWorkloadOrdinalsAndDerivedIdentity(t *testing.T) {
	p := testStore(t).WithSite(tenanttest.MobileSite())
	ctx := context.Background()
	if _, err := p.Create(ctx, "eds", tenant.Secrets{TSIG: "t", State: "s", APITokenHash: []byte{1}}, lowest); err != nil {
		t.Fatal(err)
	}

	mk := func(name string) tenant.Workload {
		return tenant.Workload{Tenant: "eds", Name: name, Cores: 2, MemoryMB: 2048, Status: tenant.StatusProvisioning}
	}
	first, err := p.CreateWorkload(ctx, mk("web"))
	if err != nil {
		t.Fatal(err)
	}
	// index 1, ordinal 0.
	if first.Ordinal != 0 || first.VMID != 2040 || first.Address != "10.20.129.10" || first.MAC != "02:de:20:00:07:f8" {
		t.Fatalf("first = %+v", first)
	}
	second, err := p.CreateWorkload(ctx, mk("db"))
	if err != nil || second.Ordinal != 1 || second.VMID != 2041 {
		t.Fatalf("second = %+v %v", second, err)
	}

	// Re-creating keeps identity and takes the sizing.
	again := mk("web")
	again.Cores, again.MemoryMB, again.DiskGB = 8, 8192, 40
	got, err := p.CreateWorkload(ctx, again)
	if err != nil || got.VMID != first.VMID || got.Ordinal != 0 || got.Cores != 8 || got.DiskGB != 40 {
		t.Fatalf("re-created = %+v %v", got, err)
	}

	if err := p.SetWorkloadStatus(ctx, "eds", "web", tenant.StatusReady); err != nil {
		t.Fatal(err)
	}
	if w, err := p.GetWorkload(ctx, "eds", "web"); err != nil || w.Status != tenant.StatusReady {
		t.Fatalf("get = %+v %v", w, err)
	}
	if ws, err := p.ListWorkloads(ctx, "eds"); err != nil || len(ws) != 2 || ws[0].Name != "web" {
		t.Fatalf("list = %+v %v", ws, err)
	}

	// A freed ordinal is reused.
	if err := p.DeleteWorkload(ctx, "eds", "web"); err != nil {
		t.Fatal(err)
	}
	third, err := p.CreateWorkload(ctx, mk("cache"))
	if err != nil || third.Ordinal != 0 || third.VMID != 2040 {
		t.Fatalf("third = %+v %v", third, err)
	}
	if _, err := p.GetWorkload(ctx, "eds", "web"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("deleted workload: %v", err)
	}
	if _, err := p.CreateWorkload(ctx, tenant.Workload{Tenant: "nobody", Name: "x", Cores: 1, MemoryMB: 1, Status: tenant.StatusProvisioning}); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("workload for an unknown tenant: %v", err)
	}
}

func TestWorkloadsAndRecordsGoWithTheirTenant(t *testing.T) {
	p := testStore(t).WithSite(tenanttest.MobileSite())
	ctx := context.Background()
	if _, err := p.Create(ctx, "eds", tenant.Secrets{TSIG: "t", State: "s", APITokenHash: []byte{1}}, lowest); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateWorkload(ctx, tenant.Workload{Tenant: "eds", Name: "web", Cores: 2, MemoryMB: 2048, Status: tenant.StatusReady}); err != nil {
		t.Fatal(err)
	}
	if err := p.PutRecord(ctx, tenant.ExtraRecord{Tenant: "eds", Name: "lightd", Address: "10.20.129.10"}); err != nil {
		t.Fatal(err)
	}
	if err := p.PutRecord(ctx, tenant.ExtraRecord{Tenant: "eds", Name: "lightd", Address: "10.20.129.11"}); err != nil {
		t.Fatal(err)
	}
	recs, err := p.ListRecords(ctx, "eds")
	if err != nil || len(recs) != 1 || recs[0].Address != "10.20.129.11" {
		t.Fatalf("records = %+v %v", recs, err)
	}
	if err := p.DeleteRecord(ctx, "eds", "lightd"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRecord(ctx, "eds", "lightd"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}

	if err := p.PutRecord(ctx, tenant.ExtraRecord{Tenant: "eds", Name: "again", Address: "10.20.129.12"}); err != nil {
		t.Fatal(err)
	}
	// Deleting the tenant takes its workloads and names with it.
	if err := p.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if ws, _ := p.ListWorkloads(ctx, "eds"); len(ws) != 0 {
		t.Errorf("workloads survived: %+v", ws)
	}
	if rs, _ := p.ListRecords(ctx, "eds"); len(rs) != 0 {
		t.Errorf("records survived: %+v", rs)
	}
}
