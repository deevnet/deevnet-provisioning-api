package minio

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func decodePolicy(t *testing.T, raw []byte) policyDoc {
	t.Helper()
	var d policyDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// Every statement of a key's policy reaches its own bucket and nothing else.
func TestKeyPolicyReachesOneBucket(t *testing.T) {
	for _, access := range []string{tenant.BucketAccessRead, tenant.BucketAccessWrite} {
		raw, err := KeyPolicy("tdemo-media", access)
		if err != nil {
			t.Fatal(err)
		}
		d := decodePolicy(t, raw)
		var actions []string
		for _, st := range d.Statement {
			if st.Principal != nil {
				t.Errorf("%s: a key policy names a principal", access)
			}
			for _, r := range st.Resource {
				if r != "arn:aws:s3:::tdemo-media" && r != "arn:aws:s3:::tdemo-media/*" {
					t.Errorf("%s: resource %q is not the key's bucket", access, r)
				}
			}
			actions = append(actions, st.Action...)
		}
		writes := slices.Contains(actions, "s3:PutObject") || slices.Contains(actions, "s3:DeleteObject") || slices.Contains(actions, "s3:DeleteObjectVersion")
		if access == tenant.BucketAccessRead && writes {
			t.Errorf("a read key may write: %v", actions)
		}
		if access == tenant.BucketAccessWrite && !writes {
			t.Errorf("a write key may not write: %v", actions)
		}
		if !slices.Contains(actions, "s3:GetObject") || !slices.Contains(actions, "s3:ListBucket") {
			t.Errorf("%s: cannot list and get: %v", access, actions)
		}
	}
	if _, err := KeyPolicy("tdemo-media", "admin"); err == nil {
		t.Error("an unknown access was given a policy")
	}
}

// Anonymous read is GetObject on the bucket's objects, and no listing.
func TestPublicReadPolicyIsGetObjectOnly(t *testing.T) {
	raw, err := PublicReadPolicy("tdemo-site")
	if err != nil {
		t.Fatal(err)
	}
	d := decodePolicy(t, raw)
	if len(d.Statement) != 1 {
		t.Fatalf("statements = %d, want 1", len(d.Statement))
	}
	st := d.Statement[0]
	if !slices.Equal(st.Action, []string{"s3:GetObject"}) || !slices.Equal(st.Resource, []string{"arn:aws:s3:::tdemo-site/*"}) {
		t.Errorf("statement = %+v", st)
	}
	if !slices.Equal(st.Principal["AWS"], []string{"*"}) {
		t.Errorf("principal = %v", st.Principal)
	}
}

func TestLifecycleRules(t *testing.T) {
	if cfg := Lifecycle(tenant.BucketSpec{}); !cfg.Empty() {
		t.Errorf("no expiry asked for, got %d rules", len(cfg.Rules))
	}
	cfg := Lifecycle(tenant.BucketSpec{ExpireDays: 30, NoncurrentExpireDays: 7})
	if len(cfg.Rules) != 2 || cfg.Rules[0].Expiration.Days != 30 || cfg.Rules[1].NoncurrentVersionExpiration.NoncurrentDays != 7 {
		t.Errorf("rules = %+v", cfg.Rules)
	}
	if !sameLifecycle(cfg, Lifecycle(tenant.BucketSpec{ExpireDays: 30, NoncurrentExpireDays: 7})) {
		t.Error("the same settings compare different")
	}
	if sameLifecycle(cfg, Lifecycle(tenant.BucketSpec{ExpireDays: 30})) {
		t.Error("a dropped rule compares the same")
	}
	if !sameLifecycle(nil, Lifecycle(tenant.BucketSpec{})) {
		t.Error("none and empty compare different")
	}
}

func TestSamePolicyIgnoresSpelling(t *testing.T) {
	a := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["x"]}]}`
	b := `{"Statement":[{"Resource":["x"],"Action":["s3:GetObject"],"Effect":"Allow"}],"Version":"2012-10-17"}`
	if !samePolicy(a, b) {
		t.Error("the same document in another order compares different")
	}
	if samePolicy(a, "") || !samePolicy("", "") {
		t.Error("an absent policy compares wrong")
	}
}

// Needs a MinIO the test may write to, as TestEnsureAndRemove. Over TLS when
// DEEVNET_TEST_MINIO_CACERT names the CA, as the site runs it; otherwise over
// plain HTTP, as `make test-integration` runs MinIO.
func TestBucketsAgainstAStore(t *testing.T) {
	ep, ca := os.Getenv("DEEVNET_TEST_MINIO_ENDPOINT"), os.Getenv("DEEVNET_TEST_MINIO_CACERT")
	if ep == "" {
		t.Skip("DEEVNET_TEST_MINIO_ENDPOINT not set")
	}
	dial := func(ak, sk string) (*madmin.AdminClient, *miniogo.Client) {
		t.Helper()
		a, s3, err := connect(ep, ak, sk, ca != "", ca, miniogo.BucketLookupPath)
		if err != nil {
			t.Fatal(err)
		}
		return a, s3
	}
	a, s3 := dial(os.Getenv("DEEVNET_TEST_MINIO_ACCESS_KEY"), os.Getenv("DEEVNET_TEST_MINIO_SECRET_KEY"))
	c := &Buckets{admin: a, s3: s3}
	ctx := context.Background()

	spec := tenant.BucketSpec{Bucket: "tprobe-media", QuotaGB: 1, Versioning: true, ExpireDays: 30, NoncurrentExpireDays: 7, PublicRead: true}
	other := tenant.BucketSpec{Bucket: "tother-media", QuotaGB: 1}
	write := tenant.BucketKeySpec{Bucket: spec.Bucket, Policy: tenant.BucketKeyPolicyName(spec.Bucket, "default"),
		AccessKey: "TPROBEACCESSKEY00001", SecretKey: "test-only-not-a-real-secret-000000000000", Access: tenant.BucketAccessWrite}
	read := tenant.BucketKeySpec{Bucket: spec.Bucket, Policy: tenant.BucketKeyPolicyName(spec.Bucket, "reader"),
		AccessKey: "TPROBEACCESSKEY00002", SecretKey: "test-only-not-a-real-secret-000000000001", Access: tenant.BucketAccessRead}
	t.Cleanup(func() {
		for _, k := range []tenant.BucketKeySpec{write, read} {
			_ = c.RemoveKey(context.Background(), k.AccessKey, k.Policy)
		}
		_ = c.RemoveBucket(context.Background(), spec.Bucket, true)
		_ = c.RemoveBucket(context.Background(), other.Bucket, true)
	})
	for i := 0; i < 2; i++ {
		if err := c.EnsureBucket(ctx, spec); err != nil {
			t.Fatalf("ensure %d: %v", i, err)
		}
		for _, k := range []tenant.BucketKeySpec{write, read} {
			if err := c.EnsureKey(ctx, k); err != nil {
				t.Fatalf("ensure key %s %d: %v", k.Policy, i, err)
			}
		}
	}
	if err := c.EnsureBucket(ctx, other); err != nil {
		t.Fatal(err)
	}
	q, err := a.GetBucketQuota(ctx, spec.Bucket)
	if err != nil || q.Type != madmin.HardQuota || (q.Size != gib && q.Quota != gib) {
		t.Errorf("quota = %+v %v", q, err)
	}
	lc, err := s3.GetBucketLifecycle(ctx, spec.Bucket)
	if err != nil || !sameLifecycle(lc, Lifecycle(spec)) {
		t.Errorf("lifecycle = %+v %v", lc, err)
	}

	// The write key writes its bucket and not another; the read key reads and
	// is refused a put.
	_, ws3 := dial(write.AccessKey, write.SecretKey)
	if _, err := ws3.PutObject(ctx, spec.Bucket, "a", bytes.NewReader([]byte("x")), 1, miniogo.PutObjectOptions{}); err != nil {
		t.Fatalf("put with the write key: %v", err)
	}
	if _, err := ws3.PutObject(ctx, other.Bucket, "a", bytes.NewReader([]byte("x")), 1, miniogo.PutObjectOptions{}); err == nil {
		t.Error("the write key wrote another bucket")
	}
	_, rs3 := dial(read.AccessKey, read.SecretKey)
	if o, err := rs3.GetObject(ctx, spec.Bucket, "a", miniogo.GetObjectOptions{}); err != nil {
		t.Errorf("get with the read key: %v", err)
	} else if _, err := o.Stat(); err != nil {
		t.Errorf("get with the read key: %v", err)
	}
	if _, err := rs3.PutObject(ctx, spec.Bucket, "b", bytes.NewReader([]byte("x")), 1, miniogo.PutObjectOptions{}); err == nil {
		t.Error("the read key wrote")
	}

	// Anonymous read gets an object, and does not list.
	anon, err := miniogo.New(ep, &miniogo.Options{Secure: ca != "", BucketLookup: miniogo.BucketLookupPath, Transport: s3Transport(t, ca)})
	if err != nil {
		t.Fatal(err)
	}
	if o, err := anon.GetObject(ctx, spec.Bucket, "a", miniogo.GetObjectOptions{}); err != nil {
		t.Errorf("anonymous get: %v", err)
	} else if _, err := o.Stat(); err != nil {
		t.Errorf("anonymous get: %v", err)
	}
	for o := range anon.ListObjects(ctx, spec.Bucket, miniogo.ListObjectsOptions{}) {
		if o.Err == nil {
			t.Error("anonymous listing was allowed")
		}
		break
	}

	// Off after on: versioning suspended, anonymous read and lifecycle gone.
	changed := spec
	changed.Versioning, changed.PublicRead, changed.ExpireDays, changed.NoncurrentExpireDays = false, false, 0, 0
	if err := c.EnsureBucket(ctx, changed); err != nil {
		t.Fatalf("ensure changed: %v", err)
	}
	if v, _ := s3.GetBucketVersioning(ctx, spec.Bucket); v.Status != "Suspended" {
		t.Errorf("versioning = %q, want Suspended", v.Status)
	}
	if pol, _ := s3.GetBucketPolicy(ctx, spec.Bucket); pol != "" {
		t.Errorf("bucket policy left: %s", pol)
	}
	if o, err := anon.GetObject(ctx, spec.Bucket, "a", miniogo.GetObjectOptions{}); err == nil {
		if _, err := o.Stat(); err == nil {
			t.Error("anonymous get still allowed")
		}
	}

	if full, err := c.BucketHasObjects(ctx, spec.Bucket); err != nil || !full {
		t.Fatalf("has objects = %v, %v", full, err)
	}
	if err := c.RemoveBucket(ctx, spec.Bucket, false); !errors.Is(err, tenant.ErrBucketNotEmpty) {
		t.Fatalf("remove without purge = %v, want ErrBucketNotEmpty", err)
	}
	for _, k := range []tenant.BucketKeySpec{write, read} {
		if err := c.RemoveKey(ctx, k.AccessKey, k.Policy); err != nil {
			t.Fatalf("remove key: %v", err)
		}
		if err := c.RemoveKey(ctx, k.AccessKey, k.Policy); err != nil {
			t.Fatalf("remove key again: %v", err)
		}
	}
	if err := c.RemoveBucket(ctx, spec.Bucket, true); err != nil {
		t.Fatalf("remove with purge: %v", err)
	}
	if err := c.RemoveBucket(ctx, spec.Bucket, true); err != nil {
		t.Fatalf("remove again: %v", err)
	}
	if full, err := c.BucketHasObjects(ctx, spec.Bucket); err != nil || full {
		t.Errorf("an absent bucket has objects = %v, %v", full, err)
	}
}

// s3Transport is a transport trusting ca, or nil for plain HTTP.
func s3Transport(t *testing.T, ca string) http.RoundTripper {
	t.Helper()
	if ca == "" {
		return nil
	}
	raw, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return tr
}
