package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func TestBucketsAdmitAndSealTheirKeys(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	for _, n := range []string{"eds", "tdemo"} {
		if _, err := p.Create(ctx, n, tenant.Secrets{APITokenHash: []byte(n)}, lowest); err != nil {
			t.Fatal(err)
		}
	}
	p.WithSealer(fakeSealer{})

	if _, err := p.PutBucket(ctx, tenant.Bucket{Tenant: "eds", Name: "media", QuotaGB: 60, Status: tenant.StatusProvisioning}, 100); err != nil {
		t.Fatal(err)
	}
	_, err := p.PutBucket(ctx, tenant.Bucket{Tenant: "tdemo", Name: "media", QuotaGB: 41, Status: tenant.StatusProvisioning}, 100)
	var ce *tenant.CapacityError
	if !errors.As(err, &ce) || ce.FreeGB != 40 {
		t.Fatalf("err = %v, want a capacity error naming 40 GB", err)
	}
	// A decrease is never refused, even under a lowered capacity.
	if _, err := p.PutBucket(ctx, tenant.Bucket{Tenant: "eds", Name: "media", QuotaGB: 50, Versioning: true, ExpireDays: 3, Status: tenant.StatusReady}, 10); err != nil {
		t.Fatalf("decrease: %v", err)
	}
	b, err := p.GetBucket(ctx, "eds", "media")
	if err != nil || b.QuotaGB != 50 || !b.Versioning || b.ExpireDays != 3 || b.Status != tenant.StatusReady {
		t.Fatalf("bucket = %+v %v", b, err)
	}
	if _, err := p.PutBucket(ctx, tenant.Bucket{Tenant: "nobody", Name: "media", QuotaGB: 1, Status: tenant.StatusProvisioning}, 100); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("bucket for an unknown tenant: %v", err)
	}

	k := tenant.BucketKey{Tenant: "eds", Bucket: "media", Name: "default", Access: "write",
		AccessKey: "AAAAAAAAAAAAAAAAAAA1", SecretKey: "test-only-secret", Status: tenant.StatusProvisioning}
	if got, err := p.PutBucketKey(ctx, k); err != nil || got.SecretKey != "test-only-secret" {
		t.Fatalf("put key = %+v %v", got, err)
	}
	var stored string
	if err := p.pool.QueryRow(ctx, `SELECT secret_key FROM tenant_bucket_keys WHERE access_key = $1`, k.AccessKey).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "vault:v1:test-only-secret" {
		t.Errorf("stored %q, want it sealed", stored)
	}
	got, err := p.GetBucketKey(ctx, "eds", "media", "default")
	if err != nil || got.SecretKey != "test-only-secret" || got.Unreadable {
		t.Fatalf("get key = %+v %v", got, err)
	}
	// An access key is one store user: no second key may take it.
	dup := k
	dup.Name = "other"
	if _, err := p.PutBucketKey(ctx, dup); err == nil {
		t.Error("two keys were given one access key")
	}
	if _, err := p.PutBucketKey(ctx, tenant.BucketKey{Tenant: "eds", Bucket: "absent", Name: "x", Access: "read",
		AccessKey: "AAAAAAAAAAAAAAAAAAA2", SecretKey: "s", Status: tenant.StatusProvisioning}); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("key for an unknown bucket: %v", err)
	}

	p.WithSealer(refusingSealer{})
	keys, err := p.ListBucketKeys(ctx, "eds", "media")
	if err != nil || len(keys) != 1 || !keys[0].Unreadable || keys[0].SecretKey != "" {
		t.Fatalf("unreadable keys = %+v %v", keys, err)
	}

	// The bucket's row takes its keys with it, and the tenant's takes both.
	if err := p.DeleteBucket(ctx, "eds", "media"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := p.ListBucketKeys(ctx, "eds", "media"); len(keys) != 0 {
		t.Errorf("keys left: %v", keys)
	}
	if _, err := p.PutBucket(ctx, tenant.Bucket{Tenant: "tdemo", Name: "media", QuotaGB: 1, Status: tenant.StatusReady}, 100); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "tdemo"); err != nil {
		t.Fatal(err)
	}
	if left, _ := p.ListBuckets(ctx, "tdemo"); len(left) != 0 {
		t.Errorf("buckets left after the tenant: %v", left)
	}
}

// Many creates at once never take more than the capacity: the lock, not luck.
func TestConcurrentBucketsNeverOvercommit(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	if _, err := p.Create(ctx, "eds", tenant.Secrets{APITokenHash: []byte("e")}, lowest); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.PutBucket(ctx, tenant.Bucket{Tenant: "eds", Name: "b" + string(rune('a'+i)) + "x", QuotaGB: 10, Status: tenant.StatusReady}, 55)
		}()
	}
	wg.Wait()
	all, err := p.ListBuckets(ctx, "eds")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("%d buckets of 10 GB were admitted under 55 GB, want 5", len(all))
	}
}
