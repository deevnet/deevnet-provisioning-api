package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func csrBody(t *testing.T, csr string, names ...string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"csr": csr, "names": names})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCertificateRouteIsImplemented(t *testing.T) {
	h, _, _ := tenantServer(t)
	rec, _ := call(t, h, http.MethodGet, "/v1/tenants/eds/certificates", "")
	if rec.Code == http.StatusNotImplemented {
		t.Fatal("the certificate routes are not registered")
	}
}

func TestATenantIsIssuedACertificateForItsOwnName(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	key := tenanttest.NewKey()

	rec, body := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console",
		csrBody(t, tenanttest.RequestFor(key, "ignored"), "www"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["fqdn"] != "console.eds.deevnet.net" || body["tenant"] != "eds" || body["name"] != "console" {
		t.Errorf("got %v / %v / %v", body["tenant"], body["name"], body["fqdn"])
	}
	names, _ := body["names"].([]any)
	if len(names) != 4 || names[0] != "console.eds.deevnet.net" || names[1] != "www.eds.deevnet.net" ||
		names[2] != "console.eds.mobile.deevnet.net" || names[3] != "www.eds.mobile.deevnet.net" {
		t.Errorf("names = %v", body["names"])
	}
	for _, field := range []string{"certificate", "ca_chain"} {
		if v, _ := body[field].(string); !strings.HasPrefix(v, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("%s = %.40q", field, body[field])
		}
	}
	for _, field := range []string{"serial", "key_fingerprint", "not_before", "not_after", "renew_after", "created_at", "updated_at"} {
		if v, _ := body[field].(string); v == "" {
			t.Errorf("%s is empty", field)
		}
	}

	// Asking again is 200 with the same certificate, not another one.
	again, second := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console",
		csrBody(t, tenanttest.RequestFor(key, "ignored"), "www"))
	if again.Code != http.StatusOK || second["serial"] != body["serial"] {
		t.Fatalf("asking again: %d, serial %v then %v", again.Code, body["serial"], second["serial"])
	}

	rec, got := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/certificates/console", "")
	if rec.Code != http.StatusOK || got["certificate"] != body["certificate"] {
		t.Errorf("get: %d", rec.Code)
	}
	rec, list := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/certificates", "")
	if certs, _ := list["certificates"].([]any); rec.Code != http.StatusOK || len(certs) != 1 {
		t.Errorf("list: %d %v", rec.Code, list)
	}
}

// A tenant with nothing renders [], not null.
func TestNoCertificatesIsAnEmptyList(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/certificates", "")
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"certificates":[]`)) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// A certificate is a statement about names in one tenant's zone. Another
// tenant's token cannot ask for it, read it or remove it, and is told the
// tenant does not exist, not that it may not.
func TestAnotherTenantCannotTouchACertificate(t *testing.T) {
	h, _, b := tenantServer(t)
	eds := createTenantFor(t, h, "eds")
	tdemo := createTenantFor(t, h, "tdemo")
	body := csrBody(t, tenanttest.Request("x"))

	if rec, _ := callAs(t, h, eds, http.MethodPut, "/v1/tenants/eds/certificates/console", body); rec.Code != http.StatusCreated {
		t.Fatalf("eds: %d", rec.Code)
	}
	signed := len(b.Signer.Calls)

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPut, "/v1/tenants/eds/certificates/console", body},
		{http.MethodPut, "/v1/tenants/eds/certificates/another", body},
		{http.MethodGet, "/v1/tenants/eds/certificates/console", ""},
		{http.MethodGet, "/v1/tenants/eds/certificates", ""},
		{http.MethodDelete, "/v1/tenants/eds/certificates/console", ""},
	} {
		rec, _ := callAs(t, h, tdemo, c.method, c.path, c.body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s as tdemo: %d", c.method, c.path, rec.Code)
		}
	}
	if len(b.Signer.Calls) != signed {
		t.Fatal("another tenant's request reached the signer")
	}
	// And with no token at all, nothing.
	if rec, _ := callAs(t, h, "", http.MethodGet, "/v1/tenants/eds/certificates", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("with no token: %d", rec.Code)
	}
	// It is still there for its owner.
	if rec, _ := callAs(t, h, eds, http.MethodGet, "/v1/tenants/eds/certificates/console", ""); rec.Code != http.StatusOK {
		t.Errorf("eds lost its certificate: %d", rec.Code)
	}
}

// The path is where a name outside the zone would be tried. A dot cannot be a
// label, and what the router makes of a slash is not a certificate.
func TestANameCannotLeaveTheZoneThroughThePath(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	body := csrBody(t, tenanttest.Request("x"))

	for _, name := range []string{
		"grafana.mobile.deevnet.net", "console.eds.mobile.deevnet.net", "a.b", "%2A", "*",
		"console%2Fx", "Console", "..", "%2e%2e",
	} {
		rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/"+name, body)
		// Refused, or sent elsewhere by the router: anything but a success.
		if rec.Code < 300 || rec.Code >= 500 {
			t.Errorf("certificate %q: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console",
		csrBody(t, tenanttest.Request("x"), "grafana.mobile.deevnet.net")); rec.Code != http.StatusBadRequest {
		t.Errorf("a further name with a dot: %d", rec.Code)
	}
	if len(b.Signer.Calls) != 0 {
		t.Fatalf("the signer was reached %d times", len(b.Signer.Calls))
	}
}

func TestACertificateBodyIsHeldToItsShape(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	csr := tenanttest.Request("x")
	quoted, _ := json.Marshal(csr)

	for name, body := range map[string]string{
		"no body":          "",
		"not JSON":         "csr",
		"an unknown field": `{"csr":` + string(quoted) + `,"common_name":"grafana.mobile.deevnet.net"}`,
		"a lifetime":       `{"csr":` + string(quoted) + `,"ttl":"87600h"}`,
		"no request":       `{}`,
		"not a request":    `{"csr":"hello"}`,
	} {
		rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// Nothing in a certificate response is secret, and that is only true if
// nothing secret can get into one.
func TestACertificateResponseCarriesNoKey(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console", csrBody(t, tenanttest.Request("x")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d", rec.Code)
	}
	for _, secret := range []string{"PRIVATE KEY", "api_token", token} {
		if bytes.Contains(rec.Body.Bytes(), []byte(secret)) {
			t.Errorf("the response carries %q", secret)
		}
	}
	// The request is not echoed either: it is the tenant's, and it has it.
	if bytes.Contains(rec.Body.Bytes(), []byte("CERTIFICATE REQUEST")) {
		t.Error("the response echoes the signing request")
	}
}

func TestAFailedSignerNamesTheStepAndNothingElse(t *testing.T) {
	h, _, b := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	b.Signer.Err = errors.New("Post https://10.20.25.21:8200/v1/pki-tenant-service/sign/tenant-service: connection refused")

	rec, body := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console", csrBody(t, tenanttest.Request("x")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if body["error"] != `backend step "certificate" failed` {
		t.Errorf("error = %v", body["error"])
	}
	for _, leak := range []string{"10.20.25.21", "8200", "pki-tenant-service", "connection refused"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(leak)) {
			t.Errorf("the body carries %q", leak)
		}
	}
}

func TestDeletingACertificate(t *testing.T) {
	h, _, _ := tenantServer(t)
	token := createTenantFor(t, h, "eds")
	callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/certificates/console", csrBody(t, tenanttest.Request("x")))

	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/certificates/console", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/certificates/console", ""); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/certificates/console", ""); rec.Code != http.StatusNotFound {
		t.Errorf("delete again: %d", rec.Code)
	}
}

func TestWithNoTenantServiceCATheRouteSaysSo(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Signer = nil
	h := New(Config{Token: "s3cret", DB: fakeDB{}, Tenants: svc})
	call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)

	rec, body := call(t, h, http.MethodPut, "/v1/tenants/eds/certificates/console", csrBody(t, tenanttest.Request("x")))
	if rec.Code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "issues no certificates") {
		t.Fatalf("%d %v", rec.Code, body)
	}
}
