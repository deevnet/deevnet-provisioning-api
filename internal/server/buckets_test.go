package server

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

const mediaBucket = `{"name":"media","quota_gb":5,"versioning":true,"lifecycle":{"expire_days":0,"noncurrent_expire_days":30},"public_read":false}`

func TestBucketCreateReturnsTheDefaultKeyOnce(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["name"] != "media" || body["bucket"] != "eds-media" || body["endpoint"] != "https://s3.site.example" ||
		body["quota_gb"] != float64(5) || body["versioning"] != true || body["public_read"] != false || body["status"] != "ready" {
		t.Errorf("bucket = %v", body)
	}
	lc, _ := body["lifecycle"].(map[string]any)
	if lc["expire_days"] != float64(0) || lc["noncurrent_expire_days"] != float64(30) {
		t.Errorf("lifecycle = %v", body["lifecycle"])
	}
	key, _ := body["key"].(map[string]any)
	if key["name"] != "default" || key["access"] != "write" {
		t.Errorf("key = %v", key)
	}
	secret, _ := key["secret_key"].(string)
	access, _ := key["access_key"].(string)
	if len(secret) != 40 || len(access) != 20 {
		t.Fatalf("the create response carried no usable key: %v", key)
	}
	if _, ok := b.Buckets.Users[access]; !ok {
		t.Error("the key never reached the store")
	}

	// No read carries a secret, or a key at all on the bucket.
	for _, path := range []string{
		"/v1/tenants/eds/buckets",
		"/v1/tenants/eds/buckets/media",
		"/v1/tenants/eds/buckets/media/keys",
		"/v1/tenants/eds/buckets/media/keys/default",
	} {
		rec, _ := callAs(t, h, token, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "secret_key") {
			t.Errorf("GET %s carries the secret: %s", path, rec.Body.String())
		}
	}
	_, got := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/buckets/media", "")
	if _, ok := got["key"]; ok {
		t.Error("a read of the bucket carries a key")
	}
	_, list := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/buckets/media/keys", "")
	keys, _ := list["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["access_key"] != access {
		t.Errorf("keys = %v", list)
	}
}

func TestBucketCreateValidationAndConflicts(t *testing.T) {
	h, _, _ := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	for _, bad := range []string{
		`{"name":"ab","quota_gb":1}`,
		`{"name":"media","quota_gb":0}`,
		`{"name":"media"}`,
		`{"name":"media","quota_gb":1,"lifecycle":{"expire_days":-1}}`,
		`{"name":"media","quota_gb":1,"region":"us-east-1"}`,
	} {
		if rec, _ := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rec.Code)
		}
	}
	if rec, _ := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket); rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: %d, want 409", rec.Code)
	}
	// Capacity: 100 GB at the fake site, 5 taken.
	rec, body := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", `{"name":"huge","quota_gb":96}`)
	if rec.Code != http.StatusConflict || !strings.Contains(body["error"].(string), "95 GB") {
		t.Errorf("past capacity: %d %v, want 409 naming 95 GB", rec.Code, body)
	}
	// And on an update that grows the quota.
	rec, _ = call(t, h, http.MethodPut, "/v1/tenants/eds/buckets/media", `{"quota_gb":101}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("update past capacity: %d, want 409", rec.Code)
	}
	rec, body = call(t, h, http.MethodPut, "/v1/tenants/eds/buckets/media", `{"quota_gb":10,"public_read":true}`)
	if rec.Code != http.StatusOK || body["quota_gb"] != float64(10) || body["public_read"] != true || body["versioning"] != false {
		t.Errorf("update: %d %v", rec.Code, body)
	}
	// The name is the path's, not the body's.
	if rec, _ := call(t, h, http.MethodPut, "/v1/tenants/eds/buckets/media", `{"name":"other","quota_gb":1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("update with a name: %d, want 400", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodGet, "/v1/tenants/eds/buckets/absent", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown bucket: %d, want 404", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodGet, "/v1/tenants/eds/buckets/media/keys/absent", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown key: %d, want 404", rec.Code)
	}
}

func TestBucketDeleteRefusesANonEmptyBucketWithoutForce(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	b.Buckets.Objects["eds-media"] = 1

	if rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/eds/buckets/media", ""); rec.Code != http.StatusConflict {
		t.Errorf("without force: %d, want 409", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/eds/buckets/media?force=maybe", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("force=maybe: %d, want 400", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodDelete, "/v1/tenants/eds/buckets/media?force=true", ""); rec.Code != http.StatusNoContent {
		t.Errorf("with force: %d, want 204", rec.Code)
	}
	if rec, _ := call(t, h, http.MethodGet, "/v1/tenants/eds/buckets/media", ""); rec.Code != http.StatusNotFound {
		t.Errorf("after delete: %d, want 404", rec.Code)
	}
}

func TestBucketKeyRoutes(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)

	rec, body := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets/media/keys", `{"name":"reader","access":"read"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["name"] != "reader" || body["access"] != "read" || body["secret_key"] == nil {
		t.Errorf("key = %v", body)
	}
	if rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets/media/keys", `{"name":"reader","access":"read"}`); rec.Code != http.StatusConflict {
		t.Errorf("duplicate key: %d, want 409", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets/media/keys", `{"name":"x","access":"admin"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad access: %d, want 400", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/buckets/absent/keys", `{"name":"x","access":"read"}`); rec.Code != http.StatusNotFound {
		t.Errorf("key on unknown bucket: %d, want 404", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/buckets/media/keys/default", ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete default: %d, want 204", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/buckets/media/keys/default", ""); rec.Code != http.StatusNotFound {
		t.Errorf("deleted key: %d, want 404", rec.Code)
	}
	if len(b.Buckets.Users) != 1 {
		t.Errorf("store users = %v, want the reader alone", b.Buckets.Users)
	}
}

// Another tenant's buckets are not found, as for every other resource.
func TestBucketsAreTheTenantsOwn(t *testing.T) {
	h, _, _ := tenantServer(t)
	eds := createTenantFor(t, h, "eds")
	tdemo := createTenantFor(t, h, "tdemo")
	callAs(t, h, eds, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/tenants/eds/buckets", ""},
		{http.MethodGet, "/v1/tenants/eds/buckets/media", ""},
		{http.MethodPost, "/v1/tenants/eds/buckets/media/keys", `{"name":"x","access":"write"}`},
		{http.MethodDelete, "/v1/tenants/eds/buckets/media?force=true", ""},
	} {
		if rec, _ := callAs(t, h, tdemo, tc.method, tc.path, tc.body); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s as tdemo: %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

func TestBucketRoutesWithoutAStoreAnswer503(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.Buckets = nil
	h := New(Config{Token: "s3cret", DB: fakeDB{}, Logger: svc.Logger, Tenants: svc})
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	rec, body := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	if rec.Code != http.StatusServiceUnavailable || body["error"] != "this site has no bucket store" {
		t.Errorf("%d %v, want 503 with a reason", rec.Code, body)
	}
	if rec, _ := call(t, h, http.MethodGet, "/v1/tenants/eds/buckets", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("list: %d, want 503", rec.Code)
	}
}

// A store failure on create answers 502 naming the step, with the bucket and
// its key so the caller can record them; the same call then converges.
func TestBucketCreateStoreFailureIs502AndResumes(t *testing.T) {
	h, _, b := tenantServer(t)
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	b.Buckets.SetFail(errors.New("dial tcp 10.20.25.30:443: refused"))

	rec, body := call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.20.25.30") {
		t.Error("the 502 names the backend")
	}
	partial, _ := body["bucket"].(map[string]any)
	key, _ := partial["key"].(map[string]any)
	first, _ := key["access_key"].(string)
	if first == "" {
		t.Fatalf("no partial bucket in %v", body)
	}

	b.Buckets.SetFail(nil)
	rec, body = call(t, h, http.MethodPost, "/v1/tenants/eds/buckets", mediaBucket)
	if rec.Code != http.StatusCreated {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	if again := body["key"].(map[string]any)["access_key"]; again != first {
		t.Errorf("the retry minted a new key: %v, first %v", again, first)
	}
}
