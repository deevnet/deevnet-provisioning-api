package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// seen is one request the fake OpenBao answered.
type seen struct {
	method, path, ns string
	body             map[string]any
}

// fakeBao answers the AppRole login itself and every other request from
// answer, keyed "<METHOD> <path>". A request with no answer is a 404, as
// OpenBao gives for a path it holds nothing at.
func fakeBao(t *testing.T, answer map[string]func(w http.ResponseWriter)) (*Client, *[]seen) {
	t.Helper()
	var mu sync.Mutex
	var reqs []seen
	c, _ := stubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			w.Write([]byte(`{"auth":{"client_token":"t","lease_duration":3600}}`))
			return
		}
		if r.Header.Get("X-Vault-Token") != "t" {
			t.Errorf("%s %s without the API's token", r.Method, r.URL.Path)
		}
		s := seen{method: r.Method, path: r.URL.EscapedPath(), ns: r.Header.Get("X-Vault-Namespace")}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			if err := json.Unmarshal(raw, &s.body); err != nil {
				t.Errorf("body is not JSON: %s", raw)
			}
		}
		mu.Lock()
		reqs = append(reqs, s)
		mu.Unlock()
		if f, ok := answer[r.Method+" "+s.path]; ok {
			f(w)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errors":[]}`))
	})
	return c, &reqs
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		w.Write([]byte(body))
	}
}

func TestEnsureNamespaceCreatesOnlyWhatIsMissing(t *testing.T) {
	ctx := context.Background()
	c, reqs := fakeBao(t, map[string]func(http.ResponseWriter){
		"POST /v1/sys/namespaces/eds": status(http.StatusOK, `{"data":{"path":"tenants/eds/"}}`),
	})
	if err := c.EnsureNamespace(ctx, "tenants", "eds"); err != nil {
		t.Fatal(err)
	}
	if len(*reqs) != 2 || (*reqs)[0].method != "GET" || (*reqs)[1].method != "POST" {
		t.Fatalf("requests = %+v, want GET then POST", *reqs)
	}
	for _, r := range *reqs {
		if r.ns != "tenants" || r.path != "/v1/sys/namespaces/eds" {
			t.Errorf("%s %s in namespace %q, want the child under tenants", r.method, r.path, r.ns)
		}
	}

	// Already there: read and nothing more.
	c, reqs = fakeBao(t, map[string]func(http.ResponseWriter){
		"GET /v1/sys/namespaces/eds": status(http.StatusOK, `{"data":{"path":"tenants/eds/"}}`),
	})
	if err := c.EnsureNamespace(ctx, "tenants", "eds"); err != nil || len(*reqs) != 1 {
		t.Fatalf("err %v, requests %+v", err, *reqs)
	}
}

func TestDeleteNamespace(t *testing.T) {
	ctx := context.Background()
	c, reqs := fakeBao(t, map[string]func(http.ResponseWriter){
		"DELETE /v1/sys/namespaces/eds": status(http.StatusOK, `{"data":{"status":"in-progress"}}`),
	})
	if err := c.DeleteNamespace(ctx, "tenants", "eds"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.ns != "tenants" || r.method != "DELETE" {
		t.Errorf("request = %+v", r)
	}
	// Already gone is success.
	c, _ = fakeBao(t, nil)
	if err := c.DeleteNamespace(ctx, "tenants", "eds"); err != nil {
		t.Errorf("a namespace already gone: %v", err)
	}
}

// The API may not list mounts, so an enable is tried, and "already in use"
// is what an ensure that already happened looks like.
func TestEnableIsIdempotent(t *testing.T) {
	ctx := context.Background()
	inUse := status(http.StatusBadRequest, `{"errors":["path is already in use at secrets/"]}`)
	c, reqs := fakeBao(t, map[string]func(http.ResponseWriter){
		"POST /v1/sys/mounts/secrets": inUse,
		"POST /v1/sys/auth/approle":   status(http.StatusBadRequest, `{"errors":["path is already in use at approle/"]}`),
	})
	if err := c.EnableKV2(ctx, "tenants/eds", "secrets"); err != nil {
		t.Errorf("KV already enabled: %v", err)
	}
	if err := c.EnableAppRole(ctx, "tenants/eds", "approle"); err != nil {
		t.Errorf("AppRole already enabled: %v", err)
	}
	kv := (*reqs)[0]
	if kv.ns != "tenants/eds" || kv.body["type"] != "kv" || kv.body["options"].(map[string]any)["version"] != "2" {
		t.Errorf("KV enable = %+v", kv)
	}
	if ar := (*reqs)[1]; ar.ns != "tenants/eds" || ar.body["type"] != "approle" {
		t.Errorf("AppRole enable = %+v", ar)
	}

	// Any other refusal is still a failure.
	c, _ = fakeBao(t, map[string]func(http.ResponseWriter){
		"POST /v1/sys/mounts/secrets": status(http.StatusBadRequest, `{"errors":["invalid backend type"]}`),
	})
	if err := c.EnableKV2(ctx, "tenants/eds", "secrets"); err == nil {
		t.Error("a refusal that is not \"already in use\" was taken for success")
	}
}

func TestReaderCalls(t *testing.T) {
	ctx := context.Background()
	ok := status(http.StatusNoContent, "")
	c, reqs := fakeBao(t, map[string]func(http.ResponseWriter){
		"PUT /v1/sys/policies/acl/reader-backend":      ok,
		"DELETE /v1/sys/policies/acl/reader-backend":   ok,
		"POST /v1/auth/approle/role/backend":           ok,
		"DELETE /v1/auth/approle/role/backend":         ok,
		"GET /v1/auth/approle/role/backend/role-id":    status(http.StatusOK, `{"data":{"role_id":"rid"}}`),
		"POST /v1/auth/approle/role/backend/secret-id": status(http.StatusOK, `{"data":{"secret_id":"sid","secret_id_accessor":"a"}}`),
	})
	ns := "tenants/eds"
	if err := c.PutPolicy(ctx, ns, "reader-backend", `path "secrets/data/a" {}`); err != nil {
		t.Fatal(err)
	}
	role := tenant.AppRole{TokenPolicies: []string{"reader-backend"}, TokenTTL: "1h", TokenMaxTTL: "24h",
		SecretIDTTL: "0", BoundCIDRs: []string{"10.20.130.10/32"}}
	if err := c.PutAppRole(ctx, ns, "approle", "backend", role); err != nil {
		t.Fatal(err)
	}
	rid, err := c.RoleID(ctx, ns, "approle", "backend")
	if err != nil || rid != "rid" {
		t.Fatalf("role ID = %q, %v", rid, err)
	}
	sid, err := c.NewSecretID(ctx, ns, "approle", "backend")
	if err != nil || sid != "sid" {
		t.Fatalf("secret ID = %q, %v", sid, err)
	}
	if err := c.DeleteAppRole(ctx, ns, "approle", "backend"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePolicy(ctx, ns, "reader-backend"); err != nil {
		t.Fatal(err)
	}
	for _, r := range *reqs {
		if r.ns != ns {
			t.Errorf("%s %s in namespace %q", r.method, r.path, r.ns)
		}
	}
	if p := (*reqs)[0].body["policy"]; p != `path "secrets/data/a" {}` {
		t.Errorf("policy body = %v", p)
	}
	ar := (*reqs)[1].body
	for _, k := range []string{"secret_id_bound_cidrs", "token_bound_cidrs"} {
		if v, _ := ar[k].([]any); len(v) != 1 || v[0] != "10.20.130.10/32" {
			t.Errorf("%s = %v", k, ar[k])
		}
	}
	if ar["secret_id_ttl"] != "0" || ar["secret_id_num_uses"] != float64(0) || ar["token_ttl"] != "1h" || ar["token_max_ttl"] != "24h" {
		t.Errorf("AppRole body = %v", ar)
	}

	// Gone: a role ID is absent, and deletes converge.
	c, _ = fakeBao(t, nil)
	if _, err := c.RoleID(ctx, ns, "approle", "backend"); !errors.Is(err, ErrAbsent) {
		t.Errorf("role ID of a missing role: %v, want ErrAbsent", err)
	}
	if err := c.DeleteAppRole(ctx, ns, "approle", "backend"); err != nil {
		t.Errorf("deleting a missing role: %v", err)
	}
	if err := c.DeletePolicy(ctx, ns, "reader-backend"); err != nil {
		t.Errorf("deleting a missing policy: %v", err)
	}
}

func TestKVCalls(t *testing.T) {
	ctx := context.Background()
	c, reqs := fakeBao(t, map[string]func(http.ResponseWriter){
		"POST /v1/secrets/data/weather/api":       status(http.StatusOK, `{"data":{"version":3}}`),
		"GET /v1/secrets/metadata/weather/api":    status(http.StatusOK, `{"data":{"current_version":3}}`),
		"DELETE /v1/secrets/metadata/weather/api": status(http.StatusNoContent, ""),
	})
	ns := "tenants/eds"
	if err := c.WriteKV(ctx, ns, "secrets", "weather/api", map[string]string{"key": "v"}); err != nil {
		t.Fatal(err)
	}
	if v, err := c.KVVersion(ctx, ns, "secrets", "weather/api"); err != nil || v != 3 {
		t.Fatalf("version = %d, %v", v, err)
	}
	if err := c.DeleteKV(ctx, ns, "secrets", "weather/api"); err != nil {
		t.Fatal(err)
	}
	w := (*reqs)[0]
	if w.ns != ns || w.body["data"].(map[string]any)["key"] != "v" {
		t.Errorf("write = %+v", w)
	}
	// Never a read of the value: the API's policy has none.
	for _, r := range *reqs {
		if r.method == "GET" && strings.Contains(r.path, "/data/") {
			t.Errorf("read a value: %s %s", r.method, r.path)
		}
	}

	c, _ = fakeBao(t, nil)
	if _, err := c.KVVersion(ctx, ns, "secrets", "weather/api"); !errors.Is(err, ErrAbsent) {
		t.Errorf("version of a missing secret: %v, want ErrAbsent", err)
	}
	if err := c.DeleteKV(ctx, ns, "secrets", "weather/api"); err != nil {
		t.Errorf("deleting a missing secret: %v", err)
	}
}

func TestSealedNamespaceCallsAreUnavailable(t *testing.T) {
	c, _ := stubClient(t, sealed)
	ctx := context.Background()
	if err := c.EnsureNamespace(ctx, "tenants", "eds"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("ensure namespace: %v", err)
	}
	if _, err := c.KVVersion(ctx, "tenants/eds", "secrets", "a"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAbsent) {
		t.Errorf("KV version: %v, want ErrUnavailable and not absent", err)
	}
	if _, err := c.RoleID(ctx, "tenants/eds", "approle", "r"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAbsent) {
		t.Errorf("role ID: %v, want ErrUnavailable and not absent", err)
	}
}
