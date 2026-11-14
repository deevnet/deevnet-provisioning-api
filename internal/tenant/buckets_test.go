package tenant_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func bucketReq(name string, quota int) tenant.BucketRequest {
	return tenant.BucketRequest{Name: name, QuotaGB: quota}
}

var (
	accessKeyRE = regexp.MustCompile(`^[A-Z0-9]{20}$`)
	secretKeyRE = regexp.MustCompile(`^[A-Za-z0-9]{40}$`)
)

// A bucket is <tenant>-<name> in the store, and comes with a write key named
// default whose secret is in the create's answer.
func TestCreateBucketMakesTheBucketAndItsDefaultKey(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	bk, k, err := svc.CreateBucket(ctx, "eds", tenant.BucketRequest{
		Name: "media", QuotaGB: 5, Versioning: true, ExpireDays: 30, NoncurrentExpireDays: 7, PublicRead: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bk.StoreName() != "eds-media" || bk.Status != tenant.StatusReady {
		t.Errorf("bucket = %+v", bk)
	}
	spec, ok := b.Buckets.Buckets["eds-media"]
	if !ok {
		t.Fatal("the bucket never reached the store")
	}
	if spec.QuotaGB != 5 || !spec.Versioning || spec.ExpireDays != 30 || spec.NoncurrentExpireDays != 7 || !spec.PublicRead {
		t.Errorf("store was told %+v", spec)
	}

	if k.Name != tenant.DefaultBucketKey || k.Access != tenant.BucketAccessWrite || k.Status != tenant.StatusReady {
		t.Errorf("default key = %+v", k)
	}
	if !accessKeyRE.MatchString(k.AccessKey) || !secretKeyRE.MatchString(k.SecretKey) {
		t.Errorf("generated key has the wrong shape: access %d chars, secret %d chars", len(k.AccessKey), len(k.SecretKey))
	}
	user, ok := b.Buckets.Users[k.AccessKey]
	if !ok || user.SecretKey != k.SecretKey || user.Bucket != "eds-media" || user.Policy != "eds-media.default" {
		t.Errorf("store user = %+v", user)
	}
}

// Two keys never share an access key or a secret.
func TestBucketKeysAreGeneratedFresh(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	_, a, err := svc.CreateBucket(ctx, "eds", bucketReq("one", 1))
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := svc.CreateBucket(ctx, "eds", bucketReq("two", 1))
	if err != nil {
		t.Fatal(err)
	}
	if a.AccessKey == b.AccessKey || a.SecretKey == b.SecretKey {
		t.Error("two keys were given the same credential")
	}
}

func TestCreateBucketValidates(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		req  tenant.BucketRequest
	}{
		{"too short", bucketReq("ab", 1)},
		{"uppercase", bucketReq("Media", 1)},
		{"starts with a digit", bucketReq("1media", 1)},
		{"ends with a dash", bucketReq("media-", 1)},
		{"a dot", bucketReq("my.media", 1)},
		{"too long", bucketReq("a"+strings.Repeat("b", 32), 1)},
		{"no quota", bucketReq("media", 0)},
		{"negative expiry", tenant.BucketRequest{Name: "media", QuotaGB: 1, ExpireDays: -1}},
		{"negative noncurrent expiry", tenant.BucketRequest{Name: "media", QuotaGB: 1, NoncurrentExpireDays: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.CreateBucket(ctx, "eds", tc.req)
			var inv *tenant.InvalidError
			if !errors.As(err, &inv) {
				t.Fatalf("err = %v, want invalid", err)
			}
		})
	}
	if len(b.Buckets.Buckets) != 0 {
		t.Errorf("an invalid bucket reached the store: %v", b.Buckets.Buckets)
	}
}

func TestBucketsNotOffered(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	svc.Buckets = nil
	if _, _, err := svc.CreateBucket(context.Background(), "eds", bucketReq("media", 1)); !errors.Is(err, tenant.ErrBucketsNotOffered) {
		t.Errorf("err = %v, want ErrBucketsNotOffered", err)
	}
	if _, err := svc.ListBuckets(context.Background(), "eds"); !errors.Is(err, tenant.ErrBucketsNotOffered) {
		t.Errorf("list err = %v", err)
	}
}

// Quotas are allocated across every tenant and never overcommitted. What is
// left is named.
func TestAdmissionRefusesPastCapacity(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()

	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 60)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateBucket(ctx, "tdemo", bucketReq("media", 30)); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.CreateBucket(ctx, "tdemo", bucketReq("backups", 11))
	var ce *tenant.CapacityError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a capacity error", err)
	}
	if ce.FreeGB != 10 || ce.CapacityGB != 100 || !strings.Contains(ce.Error(), "10 GB") {
		t.Errorf("capacity error = %+v (%s)", ce, ce)
	}
	if _, ok := b.Buckets.Buckets["tdemo-backups"]; ok {
		t.Error("a refused bucket reached the store")
	}
	// Exactly what is left fits.
	if _, _, err := svc.CreateBucket(ctx, "tdemo", bucketReq("backups", 10)); err != nil {
		t.Fatalf("the last 10 GB: %v", err)
	}
}

// Admission applies to a quota increase, and never to a decrease.
func TestUpdateBucketAdmitsIncreasesOnly(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 50)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("logs", 40)); err != nil {
		t.Fatal(err)
	}
	_, err := svc.UpdateBucket(ctx, "eds", "media", tenant.BucketRequest{QuotaGB: 61})
	var ce *tenant.CapacityError
	if !errors.As(err, &ce) || ce.FreeGB != 60 {
		t.Fatalf("err = %v, want a capacity error naming 60 GB", err)
	}
	bk, err := svc.UpdateBucket(ctx, "eds", "media", tenant.BucketRequest{QuotaGB: 60, Versioning: true})
	if err != nil || bk.QuotaGB != 60 {
		t.Fatalf("the increase that fits: %+v %v", bk, err)
	}
	if spec := b.Buckets.Buckets["eds-media"]; spec.QuotaGB != 60 || !spec.Versioning {
		t.Errorf("store was told %+v", spec)
	}
	// With capacity lowered beneath the sum, a decrease still goes through.
	svc.BucketCapacityGB = 50
	if _, err := svc.UpdateBucket(ctx, "eds", "media", tenant.BucketRequest{QuotaGB: 20}); err != nil {
		t.Fatalf("a decrease was refused: %v", err)
	}
	if _, err := svc.UpdateBucket(ctx, "eds", "absent", tenant.BucketRequest{QuotaGB: 1}); !errors.Is(err, tenant.ErrBucketNotFound) {
		t.Errorf("update of an unknown bucket: %v", err)
	}
}

// A create the store failed leaves the rows; calling it again converges on
// the same key rather than minting a second. A ready bucket is a duplicate.
func TestCreateBucketRetryConverges(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()

	b.Buckets.SetFail(errors.New("store down"))
	bk, first, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 5))
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepBuckets {
		t.Fatalf("err = %v, want the buckets step", err)
	}
	if bk.Status != tenant.StatusProvisioning || first.SecretKey == "" {
		t.Errorf("partial = %+v %+v", bk, first)
	}
	if got, _ := st.GetBucket(ctx, "eds", "media"); got.Status != tenant.StatusProvisioning {
		t.Errorf("registry status = %s", got.Status)
	}

	b.Buckets.SetFail(nil)
	_, again, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 5))
	if err != nil {
		t.Fatal(err)
	}
	if again.AccessKey != first.AccessKey || again.SecretKey != first.SecretKey {
		t.Error("a retry minted a second key")
	}
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 5)); !errors.Is(err, tenant.ErrBucketExists) {
		t.Errorf("a duplicate: %v, want ErrBucketExists", err)
	}
}

func TestBucketKeys(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}

	k, err := svc.CreateBucketKey(ctx, "eds", "media", tenant.BucketKeyRequest{Name: "reader", Access: tenant.BucketAccessRead})
	if err != nil {
		t.Fatal(err)
	}
	if k.SecretKey == "" || !accessKeyRE.MatchString(k.AccessKey) {
		t.Errorf("key = %+v", k)
	}
	if u := b.Buckets.Users[k.AccessKey]; u.Access != tenant.BucketAccessRead || u.Policy != "eds-media.reader" || u.Bucket != "eds-media" {
		t.Errorf("store user = %+v", u)
	}

	for _, bad := range []tenant.BucketKeyRequest{
		{Name: "reader", Access: "admin"},
		{Name: "Reader", Access: "read"},
		{Name: "", Access: "read"},
		{Name: "a" + strings.Repeat("b", 20), Access: "read"},
	} {
		var inv *tenant.InvalidError
		if _, err := svc.CreateBucketKey(ctx, "eds", "media", bad); !errors.As(err, &inv) {
			t.Errorf("%+v: err = %v, want invalid", bad, err)
		}
	}
	if _, err := svc.CreateBucketKey(ctx, "eds", "media", tenant.BucketKeyRequest{Name: "reader", Access: "write"}); !errors.Is(err, tenant.ErrBucketKeyExists) {
		t.Errorf("duplicate key: %v", err)
	}
	if _, err := svc.CreateBucketKey(ctx, "eds", "absent", tenant.BucketKeyRequest{Name: "x", Access: "read"}); !errors.Is(err, tenant.ErrBucketNotFound) {
		t.Errorf("key on an unknown bucket: %v", err)
	}

	keys, err := svc.ListBucketKeys(ctx, "eds", "media")
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %v %v", keys, err)
	}

	// The default key is deleted like any other.
	def, _ := svc.GetBucketKey(ctx, "eds", "media", tenant.DefaultBucketKey)
	if err := svc.DeleteBucketKey(ctx, "eds", "media", tenant.DefaultBucketKey); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Buckets.Users[def.AccessKey]; ok {
		t.Error("the deleted key's user is still in the store")
	}
	if _, ok := b.Buckets.Policies["eds-media.default"]; ok {
		t.Error("the deleted key's policy is still in the store")
	}
	if _, err := svc.GetBucketKey(ctx, "eds", "media", tenant.DefaultBucketKey); !errors.Is(err, tenant.ErrBucketKeyNotFound) {
		t.Errorf("read after delete: %v", err)
	}
}

// A bucket holding anything is refused without force, and nothing changes;
// with force it is emptied, then removed with its keys and policies.
func TestDeleteBucketNeedsForceWhenNotEmpty(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	_, k, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1))
	if err != nil {
		t.Fatal(err)
	}
	b.Buckets.Objects["eds-media"] = 3

	if err := svc.DeleteBucket(ctx, "eds", "media", false); !errors.Is(err, tenant.ErrBucketNotEmpty) {
		t.Fatalf("err = %v, want ErrBucketNotEmpty", err)
	}
	if got, _ := st.GetBucket(ctx, "eds", "media"); got.Status != tenant.StatusReady {
		t.Errorf("a refused delete changed the status to %s", got.Status)
	}
	if _, ok := b.Buckets.Users[k.AccessKey]; !ok {
		t.Error("a refused delete removed a key")
	}

	if err := svc.DeleteBucket(ctx, "eds", "media", true); err != nil {
		t.Fatal(err)
	}
	if len(b.Buckets.Purged) != 1 || b.Buckets.Purged[0] != "eds-media" {
		t.Errorf("purged = %v", b.Buckets.Purged)
	}
	if len(b.Buckets.Buckets)+len(b.Buckets.Users)+len(b.Buckets.Policies) != 0 {
		t.Errorf("left in the store: %v %v %v", b.Buckets.Buckets, b.Buckets.Users, b.Buckets.Policies)
	}
	if _, err := svc.GetBucket(ctx, "eds", "media"); !errors.Is(err, tenant.ErrBucketNotFound) {
		t.Errorf("read after delete: %v", err)
	}
	if keys, _ := st.ListBucketKeys(ctx, "eds", "media"); len(keys) != 0 {
		t.Errorf("key rows left: %v", keys)
	}
}

func TestDeleteEmptyBucketWithoutForce(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteBucket(ctx, "eds", "media", false); err != nil {
		t.Fatal(err)
	}
	if len(b.Buckets.Buckets) != 0 || len(b.Buckets.Purged) != 0 {
		t.Errorf("store = %v, purged %v", b.Buckets.Buckets, b.Buckets.Purged)
	}
	if err := svc.DeleteBucket(ctx, "eds", "media", false); !errors.Is(err, tenant.ErrBucketNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

// A reconcile makes every bucket and key again in a rebuilt store, with the
// secret the registry kept, and finishes a create the store had failed.
func TestReconcileMakesBucketsAndKeysAgain(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	_, def, err := svc.CreateBucket(ctx, "eds", tenant.BucketRequest{Name: "media", QuotaGB: 3, Versioning: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := svc.CreateBucketKey(ctx, "eds", "media", tenant.BucketKeyRequest{Name: "reader", Access: tenant.BucketAccessRead})
	if err != nil {
		t.Fatal(err)
	}
	b.Buckets.SetFail(errors.New("store down"))
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("half", 1)); err == nil {
		t.Fatal("the failing store accepted a bucket")
	}
	b.Buckets.SetFail(nil)

	// The store is rebuilt empty.
	fresh := tenanttest.NewBucketStore()
	svc.Buckets = fresh
	if _, err := svc.Reconcile(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if spec := fresh.Buckets["eds-media"]; spec.QuotaGB != 3 || !spec.Versioning {
		t.Errorf("media = %+v", spec)
	}
	if _, ok := fresh.Buckets["eds-half"]; !ok {
		t.Error("the half-made bucket was not finished")
	}
	if u := fresh.Users[def.AccessKey]; u.SecretKey != def.SecretKey || u.Access != tenant.BucketAccessWrite {
		t.Errorf("default key user = %+v", u)
	}
	if u := fresh.Users[reader.AccessKey]; u.SecretKey != reader.SecretKey || u.Access != tenant.BucketAccessRead {
		t.Errorf("reader key user = %+v", u)
	}
	if got, _ := st.GetBucket(ctx, "eds", "half"); got.Status != tenant.StatusReady {
		t.Errorf("half status = %s, want ready", got.Status)
	}
	rec, _ := st.Get(ctx, "eds")
	found := false
	for _, s := range rec.Steps {
		if s.Name == tenant.StepBuckets && s.OK {
			found = true
		}
	}
	if !found {
		t.Errorf("no successful buckets step recorded: %v", rec.Steps)
	}
}

// A store failure on reconcile is a failed step, and the tenant waits in
// provisioning for the next one.
func TestReconcileRecordsAFailedBucketsStep(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}
	b.Buckets.SetFail(errors.New("store down"))
	_, err := svc.Reconcile(ctx, "eds")
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepBuckets {
		t.Fatalf("err = %v, want the buckets step", err)
	}
	if rec, _ := st.Get(ctx, "eds"); rec.Status != tenant.StatusProvisioning {
		t.Errorf("status = %s", rec.Status)
	}
}

// Removing a tenant empties and removes its buckets, keys and policies, and
// leaves another tenant's alone.
func TestTenantRemovalRemovesItsBuckets(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateBucketKey(ctx, "eds", "media", tenant.BucketKeyRequest{Name: "reader", Access: "read"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateBucket(ctx, "tdemo", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}
	b.Buckets.Objects["eds-media"] = 5

	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Buckets.Buckets["eds-media"]; ok {
		t.Error("the removed tenant's bucket is still in the store")
	}
	if len(b.Buckets.Purged) != 1 || b.Buckets.Purged[0] != "eds-media" {
		t.Errorf("purged = %v", b.Buckets.Purged)
	}
	for _, u := range b.Buckets.Users {
		if u.Bucket != "tdemo-media" {
			t.Errorf("user left for %s", u.Bucket)
		}
	}
	for p := range b.Buckets.Policies {
		if !strings.HasPrefix(p, "tdemo-media.") {
			t.Errorf("policy left: %s", p)
		}
	}
	if _, ok := b.Buckets.Buckets["tdemo-media"]; !ok {
		t.Error("another tenant's bucket went too")
	}
	if left, _ := st.ListBuckets(ctx, "eds"); len(left) != 0 {
		t.Errorf("bucket rows left: %v", left)
	}
}

// A store that will not remove a bucket fails removal at the buckets step,
// and the tenant is kept for a retry.
func TestTenantRemovalStopsAtAFailedBucketsStep(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1)); err != nil {
		t.Fatal(err)
	}
	b.Buckets.SetFail(errors.New("store down"))
	err := svc.Delete(ctx, "eds")
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepBuckets {
		t.Fatalf("err = %v, want the buckets step", err)
	}
	if _, err := st.Get(ctx, "eds"); err != nil {
		t.Errorf("the tenant was removed anyway: %v", err)
	}
}

// Secrets never reach the audit log.
func TestBucketAuditCarriesNoSecret(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	_, def, err := svc.CreateBucket(ctx, "eds", bucketReq("media", 1))
	if err != nil {
		t.Fatal(err)
	}
	k, err := svc.CreateBucketKey(ctx, "eds", "media", tenant.BucketKeyRequest{Name: "reader", Access: "read"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range st.AuditLog {
		for _, v := range e.Detail {
			if s, ok := v.(string); ok && (s == def.SecretKey || s == k.SecretKey) {
				t.Errorf("audit %s carries a secret", e.Action)
			}
		}
	}
}
