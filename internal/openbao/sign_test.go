package openbao

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// bao is a stand-in for OpenBao that knows two things: logging in, and one
// signing role. It records what it was asked to sign.
type bao struct {
	mu     sync.Mutex
	paths  []string
	bodies []map[string]any
	status int
	answer string
}

func (b *bao) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/auth/approle/login" {
		_, _ = io.WriteString(w, `{"auth":{"client_token":"t","lease_duration":3600}}`)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	b.paths = append(b.paths, r.Method+" "+r.URL.Path)
	b.bodies = append(b.bodies, body)
	b.mu.Unlock()
	if b.status != 0 {
		w.WriteHeader(b.status)
	}
	_, _ = io.WriteString(w, b.answer)
}

func signingClient(t *testing.T, b *bao, mount, role string) *Client {
	t.Helper()
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	c, err := New(Config{Addr: srv.URL, RoleID: "r", SecretID: "s", KVMount: "deevnet-api",
		TransitKey: "tenant-secrets", ServiceMount: mount, ServiceRole: role})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The names go beside the request, on the one role, and nothing else does:
// no lifetime, no usage, nothing a caller could use to ask for more than the
// role gives.
func TestSignServerAsksTheOneRoleAndSendsOnlyNames(t *testing.T) {
	b := &bao{answer: `{"data":{"certificate":"LEAF","issuing_ca":"ISSUING","ca_chain":["ISSUING","SITE"]}}`}
	c := signingClient(t, b, "pki-tenant-service", "tenant-service")

	got, err := c.SignServer(context.Background(), "CSR",
		[]string{"console.eds.mobile.deevnet.net", "www.eds.mobile.deevnet.net", "lightd.eds.mobile.deevnet.net"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Certificate != "LEAF" || strings.Join(got.Chain, ",") != "ISSUING,SITE" {
		t.Fatalf("got %+v", got)
	}
	if len(b.paths) != 1 || b.paths[0] != "POST /v1/pki-tenant-service/sign/tenant-service" {
		t.Fatalf("called %v", b.paths)
	}
	body := b.bodies[0]
	want := map[string]any{
		"csr":         "CSR",
		"common_name": "console.eds.mobile.deevnet.net",
		"alt_names":   "www.eds.mobile.deevnet.net,lightd.eds.mobile.deevnet.net",
		"format":      "pem",
	}
	if len(body) != len(want) {
		t.Fatalf("sent %v, want exactly %v", body, want)
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
}

func TestSignServerWithOneNameSendsNoOthers(t *testing.T) {
	b := &bao{answer: `{"data":{"certificate":"LEAF","issuing_ca":"ISSUING"}}`}
	c := signingClient(t, b, "pki-tenant-service", "tenant-service")
	got, err := c.SignServer(context.Background(), "CSR", []string{"console.eds.mobile.deevnet.net"})
	if err != nil {
		t.Fatal(err)
	}
	if _, sent := b.bodies[0]["alt_names"]; sent {
		t.Errorf("alt_names was sent: %v", b.bodies[0])
	}
	// With no chain in the answer, the issuing CA is the chain.
	if len(got.Chain) != 1 || got.Chain[0] != "ISSUING" {
		t.Errorf("chain = %v", got.Chain)
	}
}

func TestSignServerFailures(t *testing.T) {
	ctx := context.Background()

	// A role that refuses a name answers 400, and that is an error, not a
	// certificate.
	refused := &bao{status: http.StatusBadRequest, answer: `{"errors":["common name grafana.mobile.deevnet.net not allowed by this role"]}`}
	if _, err := signingClient(t, refused, "pki-tenant-service", "tenant-service").
		SignServer(ctx, "CSR", []string{"grafana.mobile.deevnet.net"}); err == nil {
		t.Error("a refused name came back without an error")
	}

	empty := &bao{answer: `{"data":{}}`}
	if _, err := signingClient(t, empty, "pki-tenant-service", "tenant-service").
		SignServer(ctx, "CSR", []string{"console.eds.mobile.deevnet.net"}); err == nil {
		t.Error("an answer with no certificate came back without an error")
	}

	unset := &bao{}
	if _, err := signingClient(t, unset, "", "tenant-service").
		SignServer(ctx, "CSR", []string{"console.eds.mobile.deevnet.net"}); err == nil {
		t.Error("a client with no mount signed")
	}
	if _, err := signingClient(t, unset, "pki-tenant-service", "tenant-service").SignServer(ctx, "CSR", nil); err == nil {
		t.Error("a certificate with no name was asked for")
	}
	if len(unset.paths) != 0 {
		t.Errorf("OpenBao was called: %v", unset.paths)
	}
}
