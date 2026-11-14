package store

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func TestRuntimeSecretRoundTrip(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	first, err := p.PutRuntimeSecret(ctx, tenant.RuntimeSecret{Tenant: "eds", Path: "weather/api", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.PutRuntimeSecret(ctx, tenant.RuntimeSecret{Tenant: "eds", Path: "weather/api", Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("second put = %+v, first created %v", second, first.CreatedAt)
	}
	got, err := p.GetRuntimeSecret(ctx, "eds", "weather/api")
	if err != nil || got.Version != 2 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	// The table refuses a path the service would have refused.
	if _, err := p.PutRuntimeSecret(ctx, tenant.RuntimeSecret{Tenant: "eds", Path: "../x", Version: 1}); err == nil {
		t.Error("a path outside the rule was stored")
	}
	if _, err := p.PutRuntimeSecret(ctx, tenant.RuntimeSecret{Tenant: "ghost", Path: "x", Version: 1}); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a secret for a tenant that does not exist: %v", err)
	}
	if err := p.DeleteRuntimeSecret(ctx, "eds", "weather/api"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRuntimeSecret(ctx, "eds", "weather/api"); err != nil {
		t.Errorf("a repeated delete: %v", err)
	}
	if _, err := p.GetRuntimeSecret(ctx, "eds", "weather/api"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestSecretReadersBelongToATenantAndGoWithIt(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedTenantFor(t, p, "tdemo")

	if _, err := p.PutRuntimeSecret(ctx, tenant.RuntimeSecret{Tenant: "eds", Path: "a", Version: 1}); err != nil {
		t.Fatal(err)
	}
	r, err := p.PutSecretReader(ctx, tenant.SecretReader{Tenant: "eds", Name: "backend", Workload: "web", Paths: []string{"a", "b/c"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Paths) != 2 || r.Paths[1] != "b/c" || r.Workload != "web" {
		t.Errorf("put = %+v", r)
	}
	if _, err := p.PutSecretReader(ctx, tenant.SecretReader{Tenant: "eds", Name: "backend", Workload: "api", Paths: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetSecretReader(ctx, "eds", "backend")
	if err != nil || got.Workload != "api" || len(got.Paths) != 1 {
		t.Fatalf("get after replace = %+v, %v", got, err)
	}
	if _, err := p.GetSecretReader(ctx, "tdemo", "backend"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("tdemo reads eds's reader: %v", err)
	}
	if list, _ := p.ListSecretReaders(ctx, "eds"); len(list) != 1 {
		t.Errorf("list = %+v", list)
	}
	if err := p.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	seedTenantFor(t, p, "eds")
	if list, _ := p.ListSecretReaders(ctx, "eds"); len(list) != 0 {
		t.Errorf("a tenant made again holds readers %+v", list)
	}
	if _, err := p.GetRuntimeSecret(ctx, "eds", "a"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a tenant made again holds a secret: %v", err)
	}
}
