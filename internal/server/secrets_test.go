package server

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// edsWithSecret makes eds with workload web and a secret at weather/api.
func edsWithSecret(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	if rec, _ := callAs(t, h, token, http.MethodPost, "/v1/tenants/eds/workloads", `{"name":"web"}`); rec.Code >= 300 {
		t.Fatalf("workload: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/secrets/weather/api",
		`{"data":{"key":"s3cr3t-value"},"version":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put secret: %d %s", rec.Code, rec.Body.String())
	}
	return h, token
}

func TestSecretPutAndGetNeverCarryTheValue(t *testing.T) {
	h, token := edsWithSecret(t)
	for _, m := range []string{http.MethodPut, http.MethodGet} {
		body := ""
		if m == http.MethodPut {
			body = `{"data":{"key":"s3cr3t-value"},"version":2}`
		}
		rec, out := callAs(t, h, token, m, "/v1/tenants/eds/secrets/weather/api", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", m, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "s3cr3t") {
			t.Errorf("%s answered with the value: %s", m, rec.Body.String())
		}
		if out["path"] != "weather/api" || out["version"] != float64(2) || out["present"] != true || len(out) != 3 {
			t.Errorf("%s = %v", m, out)
		}
	}
	// The path may come as one escaped segment.
	rec, out := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/secrets/weather%2Fapi", "")
	if rec.Code != http.StatusOK || out["path"] != "weather/api" {
		t.Errorf("escaped path: %d %v", rec.Code, out)
	}
}

func TestSecretRoutesRefuseAndForget(t *testing.T) {
	h, token := edsWithSecret(t)
	for _, tc := range []struct{ path, body string }{
		{"/v1/tenants/eds/secrets/Weather", `{"data":{"k":"v"},"version":1}`},
		{"/v1/tenants/eds/secrets/a/b/c/d/e", `{"data":{"k":"v"},"version":1}`},
		{"/v1/tenants/eds/secrets/a", `{"data":{"k":"v"},"version":0}`},
		{"/v1/tenants/eds/secrets/a", `{"data":{"k":"v"},"version":1,"extra":1}`},
	} {
		if rec, _ := callAs(t, h, token, http.MethodPut, tc.path, tc.body); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s %s: %d, want 400", tc.path, tc.body, rec.Code)
		}
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/secrets/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("an undeclared secret: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/secrets/weather/api", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/secrets/weather/api", ""); rec.Code != http.StatusNotFound {
		t.Errorf("after delete: %d", rec.Code)
	}
}

func TestSecretReaderCredentialOnPutOnly(t *testing.T) {
	h, token := edsWithSecret(t)
	rec, out := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/secret-readers/backend",
		`{"workload":"web","paths":["weather/api"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if out["name"] != "backend" || out["workload"] != "web" || out["role_id"] == "" || out["secret_id"] == "" ||
		out["namespace"] != "tenants/eds" || out["addr"] != "https://bao.site.example:8200" {
		t.Errorf("put = %v", out)
	}
	if p, _ := out["paths"].([]any); len(p) != 1 || p[0] != "weather/api" {
		t.Errorf("paths = %v", out["paths"])
	}
	rec, got := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/secret-readers/backend", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	if _, ok := got["secret_id"]; ok {
		t.Errorf("a read carried the secret ID: %v", got)
	}
	if got["role_id"] != out["role_id"] {
		t.Errorf("role ID %v, then %v", out["role_id"], got["role_id"])
	}
	if rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/secret-readers/other",
		`{"workload":"web","paths":["undeclared"]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an undeclared path: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/secret-readers/backend", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/secret-readers/backend", ""); rec.Code != http.StatusNotFound {
		t.Errorf("after delete: %d", rec.Code)
	}
}

// Another tenant's token is told the tenant does not exist, for every route.
func TestSecretRoutesRefuseAnotherTenant(t *testing.T) {
	h, _ := edsWithSecret(t)
	other := createTenantFor(t, h, "tdemo")
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/tenants/eds/secrets/weather/api", ""},
		{http.MethodPut, "/v1/tenants/eds/secrets/weather/api", `{"data":{"k":"v"},"version":9}`},
		{http.MethodDelete, "/v1/tenants/eds/secrets/weather/api", ""},
		{http.MethodPut, "/v1/tenants/eds/secret-readers/r", `{"workload":"web","paths":["weather/api"]}`},
		{http.MethodGet, "/v1/tenants/eds/secret-readers/r", ""},
		{http.MethodDelete, "/v1/tenants/eds/secret-readers/r", ""},
	} {
		if rec, _ := callAs(t, h, other, tc.method, tc.path, tc.body); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s with tdemo's token: %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	if rec, out := call(t, h, http.MethodGet, "/v1/tenants/eds/secrets/weather/api", ""); rec.Code != http.StatusOK || out["version"] != float64(1) {
		t.Errorf("the secret changed: %d %v", rec.Code, out)
	}
}

func TestSecretsNotOfferedIs501(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.TenantSecrets = nil
	h := New(Config{Token: "s3cret", DB: fakeDB{}, Logger: svc.Logger, Tenants: svc})
	createTenantFor(t, h, "eds")
	rec, out := call(t, h, http.MethodGet, "/v1/tenants/eds/secrets/a", "")
	if rec.Code != http.StatusNotImplemented || out["error"] != tenant.ErrSecretsNotOffered.Error() {
		t.Errorf("%d %v", rec.Code, out)
	}
}

func TestSecretsSealedIs503(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	b.Bao.Err = tenant.ErrSecretsUnavailable
	rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/secrets/a", `{"data":{"k":"v"},"version":1}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("sealed: %d %s", rec.Code, rec.Body.String())
	}
}
