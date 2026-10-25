package openbao

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stubClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{Addr: srv.URL, RoleID: "r", SecretID: "s", KVMount: "kv", TransitKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

// What OpenBao answers on every path while sealed, health included.
func sealed(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(`{"errors":["Vault is sealed"]}`))
}

func TestSealedIsUnavailable(t *testing.T) {
	c, _ := stubClient(t, sealed)
	ctx := context.Background()
	if _, err := c.Open(ctx, "vault:v1:abc"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("open: %v, want ErrUnavailable", err)
	}
	if _, err := c.Seal(ctx, "x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("seal: %v, want ErrUnavailable", err)
	}
	if _, err := c.ReadKV(ctx, "backends"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("KV: %v, want ErrUnavailable", err)
	}
	if _, err := c.Unwrap(ctx, "s.tok"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("unwrap: %v, want ErrUnavailable, not ErrNotRedeemable", err)
	}
	if got := c.Health(ctx); got != "sealed" {
		t.Errorf("health = %q, want sealed", got)
	}
}

func TestUnreachableIsUnavailable(t *testing.T) {
	c, srv := stubClient(t, sealed)
	srv.Close()
	ctx := context.Background()
	if _, err := c.Open(ctx, "vault:v1:abc"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("open: %v, want ErrUnavailable", err)
	}
	if got := c.Health(ctx); got != "unreachable" {
		t.Errorf("health = %q, want unreachable", got)
	}
}

// A ciphertext the key will not open is a lost secret, and must stay one: it
// is what lets a tenant supply its secrets again after a Transit key rebuild.
func TestARefusedDecryptIsNotUnavailable(t *testing.T) {
	c, _ := stubClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			w.Write([]byte(`{"auth":{"client_token":"t","lease_duration":3600}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/"):
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors":["cipher: message authentication failed"]}`))
		case r.URL.Path == "/v1/sys/health":
			w.Write([]byte(`{"sealed":false}`))
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	_, err := c.Open(ctx, "vault:v1:abc")
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("open: %v, want a refusal that is not ErrUnavailable", err)
	}
	if got := c.Health(ctx); got != "ok" {
		t.Errorf("health = %q, want ok", got)
	}
}

func TestUninitialized(t *testing.T) {
	c, _ := stubClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotImplemented) })
	if got := c.Health(context.Background()); got != "uninitialized" {
		t.Errorf("health = %q, want uninitialized", got)
	}
}

// The caller giving up is not OpenBao being down.
func TestACancelledCallIsNotUnavailable(t *testing.T) {
	c, _ := stubClient(t, sealed)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Open(ctx, "vault:v1:abc"); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("open: %v, want the context's error", err)
	}
}
