package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// fakeBuckets is the store, in memory: what the kit asked of it.
type fakeBuckets struct {
	buckets map[string]tenant.BucketSpec
	keys    map[string]tenant.BucketKeySpec // by access key
	objects map[string]bool
}

func (f *fakeBuckets) EnsureBucket(_ context.Context, b tenant.BucketSpec) error {
	f.buckets[b.Bucket] = b
	return nil
}
func (f *fakeBuckets) BucketHasObjects(_ context.Context, b string) (bool, error) {
	return f.objects[b], nil
}
func (f *fakeBuckets) RemoveBucket(_ context.Context, b string, purge bool) error {
	if f.objects[b] && !purge {
		return tenant.ErrBucketNotEmpty
	}
	delete(f.buckets, b)
	return nil
}
func (f *fakeBuckets) EnsureKey(_ context.Context, k tenant.BucketKeySpec) error {
	f.keys[k.AccessKey] = k
	return nil
}
func (f *fakeBuckets) RemoveKey(_ context.Context, accessKey, _ string) error {
	delete(f.keys, accessKey)
	return nil
}

func bucketKit(t *testing.T, freeGB int) (*kit, *fakeBuckets) {
	t.Helper()
	k, _ := initKit(t, "tenant=tdemo\nindex=1\n")
	f := &fakeBuckets{buckets: map[string]tenant.BucketSpec{}, keys: map[string]tenant.BucketKeySpec{}, objects: map[string]bool{}}
	origStore, origStat := bucketStore, checkCapacityStat
	bucketStore = func(*kit, state) (tenant.BucketStore, error) { return f, nil }
	checkCapacityStat = func(string) (int, error) { return freeGB, nil }
	t.Cleanup(func() { bucketStore, checkCapacityStat = origStore, origStat })
	return k, f
}

func TestBucketAddMakesTheBucketAndItsWriteKey(t *testing.T) {
	k, f := bucketKit(t, 50)
	var out bytes.Buffer
	if err := k.cmdBucket(&out, []string{"add", "files", "--quota-gb", "5", "--versioning", "--noncurrent-expire-days", "30"}); err != nil {
		t.Fatal(err)
	}
	b, ok := f.buckets["tdemo-files"]
	if !ok || b.QuotaGB != 5 || !b.Versioning || b.NoncurrentExpireDays != 30 {
		t.Fatalf("store has %+v", f.buckets)
	}
	if len(f.keys) != 1 {
		t.Fatalf("keys %+v", f.keys)
	}
	for _, key := range f.keys {
		if key.Access != tenant.BucketAccessWrite || key.Policy != "tdemo-files.default" || len(key.AccessKey) != 20 || len(key.SecretKey) != 40 {
			t.Errorf("default key %+v", key)
		}
	}
	st := mustState(t, k)
	if st.SiloRootUser == "" || st.SiloRootPassword == "" {
		t.Error("no root login for the store")
	}
	if env := string(mustRead(t, k.siloEnv())); !strings.Contains(env, "MINIO_ROOT_USER="+st.SiloRootUser) || !strings.Contains(env, "MINIO_BROWSER=off") {
		t.Errorf("silo.env:\n%s", env)
	}
	if target, err := os.Readlink(filepath.Join(k.siloCertsDir(), "public.crt")); err != nil || target != "/etc/deevnet-kit/tls/server.pem" {
		t.Errorf("public.crt -> %q, %v", target, err)
	}
}

func TestBucketRules(t *testing.T) {
	k, _ := bucketKit(t, 10)
	var out bytes.Buffer
	for name, args := range map[string][]string{
		"no quota":       {"add", "files"},
		"bad name":       {"add", "Files", "--quota-gb", "1"},
		"over the card":  {"add", "big", "--quota-gb", "10"},
		"negative days":  {"add", "files", "--quota-gb", "1", "--expire-days", "-1"},
		"name not first": {"add", "--quota-gb", "1", "files"},
	} {
		if err := k.cmdBucket(&out, args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := k.cmdBucket(&out, []string{"add", "files", "--quota-gb", "4"}); err != nil {
		t.Fatal(err)
	}
	if err := k.cmdBucket(&out, []string{"add", "files", "--quota-gb", "1"}); !errors.Is(err, tenant.ErrBucketExists) {
		t.Errorf("a second files: %v", err)
	}
	// 4 + 5 + the reserve is more than 10.
	var capErr *tenant.CapacityError
	if err := k.cmdBucket(&out, []string{"add", "more", "--quota-gb", "6"}); !errors.As(err, &capErr) {
		t.Errorf("past the card: %v", err)
	}
	if err := k.cmdBucket(&out, []string{"key", "add", "files", "app", "--access", "admin"}); err == nil {
		t.Error("access admin accepted")
	}
}

// A key from the tenant's Terraform is kept, so an app's settings carry over.
func TestBucketKeyAdoptsAKeyFromTerraform(t *testing.T) {
	k, f := bucketKit(t, 50)
	var out bytes.Buffer
	if err := k.cmdBucket(&out, []string{"add", "files", "--quota-gb", "2"}); err != nil {
		t.Fatal(err)
	}
	kf := writeTemp(t, "reader.json", []byte(`{"access_key":"TDEMOREADER000000001","secret_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	if err := k.cmdBucket(&out, []string{"key", "add", "files", "reader", "--access", "read", "--key-file", kf}); err != nil {
		t.Fatal(err)
	}
	got, ok := f.keys["TDEMOREADER000000001"]
	if !ok || got.Access != tenant.BucketAccessRead || got.Policy != "tdemo-files.reader" {
		t.Fatalf("keys %+v", f.keys)
	}

	st := mustState(t, k)
	env, err := k.bucketEnv(st, "bench.local", []string{"files:reader"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"BUCKET_FILES=tdemo-files\n", "BUCKET_FILES_ACCESS_KEY=TDEMOREADER000000001\n", "BUCKET_FILES_SECRET_KEY=aaaa"} {
		if !strings.Contains(env, want) {
			t.Errorf("bucket env lacks %q:\n%s", want, env)
		}
	}
	if !strings.Contains(kitEnv(st, "bench.local", appCreds{}), "S3_ENDPOINT=https://bench.local:9000\n") {
		t.Error("kit.env has no S3_ENDPOINT")
	}

	if err := k.cmdBucket(&out, []string{"key", "rm", "files", "reader"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.keys["TDEMOREADER000000001"]; ok {
		t.Error("the key is still in the store")
	}
}

func TestBucketRmRefusesABucketWithObjects(t *testing.T) {
	k, f := bucketKit(t, 50)
	var out bytes.Buffer
	if err := k.cmdBucket(&out, []string{"add", "files", "--quota-gb", "2"}); err != nil {
		t.Fatal(err)
	}
	f.objects["tdemo-files"] = true
	if err := k.cmdBucket(&out, []string{"rm", "files"}); !errors.Is(err, tenant.ErrBucketNotEmpty) {
		t.Fatalf("rm: %v", err)
	}
	if err := k.cmdBucket(&out, []string{"rm", "files", "--force"}); err != nil {
		t.Fatal(err)
	}
	if len(f.buckets) != 0 || len(f.keys) != 0 {
		t.Errorf("left %+v %+v", f.buckets, f.keys)
	}
	if _, err := k.loadBucket("files"); !errors.Is(err, tenant.ErrBucketNotFound) {
		t.Errorf("the card still holds it: %v", err)
	}
}
