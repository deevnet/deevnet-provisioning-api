package openbao

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Needs an OpenBao with the deevnet.mgmt openbao role's engines and the
// deevnet-api AppRole: DEEVNET_TEST_OPENBAO_ADDR, _CACERT, _ROLE_ID,
// _SECRET_ID, and a KV secret "backends" holding powerdns_api_key.
func testClient(t *testing.T) *Client {
	t.Helper()
	addr := os.Getenv("DEEVNET_TEST_OPENBAO_ADDR")
	if addr == "" {
		t.Skip("DEEVNET_TEST_OPENBAO_ADDR not set")
	}
	c, err := New(Config{
		Addr:       addr,
		CAFile:     os.Getenv("DEEVNET_TEST_OPENBAO_CACERT"),
		RoleID:     os.Getenv("DEEVNET_TEST_OPENBAO_ROLE_ID"),
		SecretID:   os.Getenv("DEEVNET_TEST_OPENBAO_SECRET_ID"),
		KVMount:    "deevnet-api",
		TransitKey: "tenant-secrets",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKVTransitAndWrapping(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	kv, err := c.ReadKV(ctx, "backends")
	if err != nil {
		t.Fatalf("read KV: %v", err)
	}
	if kv["powerdns_api_key"] == "" {
		t.Fatalf("KV backends has no powerdns_api_key: keys %v", keys(kv))
	}

	ct, err := c.Seal(ctx, "tsig secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !strings.HasPrefix(ct, CiphertextPrefix) || strings.Contains(ct, "tsig") {
		t.Fatalf("ciphertext %q is not a Transit ciphertext", ct)
	}
	pt, err := c.Open(ctx, ct)
	if err != nil || pt != "tsig secret" {
		t.Fatalf("open = %q, %v", pt, err)
	}
	if legacy, err := c.Open(ctx, "stored-before-encryption"); err != nil || legacy != "stored-before-encryption" {
		t.Fatalf("a value without the prefix must read as it is: %q %v", legacy, err)
	}

	tok, expires, err := c.Wrap(ctx, map[string]string{"tenant": "tdemo"}, time.Hour)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if time.Until(expires) < 50*time.Minute {
		t.Errorf("expires %v, want about an hour from now", expires)
	}
	got, err := c.Unwrap(ctx, tok)
	if err != nil || got["tenant"] != "tdemo" {
		t.Fatalf("unwrap = %v, %v", got, err)
	}
	if _, err := c.Unwrap(ctx, tok); !errors.Is(err, ErrNotRedeemable) {
		t.Fatalf("second unwrap: %v, want ErrNotRedeemable", err)
	}
	if _, err := c.Unwrap(ctx, "s.not-a-token"); !errors.Is(err, ErrNotRedeemable) {
		t.Fatalf("bogus token: %v, want ErrNotRedeemable", err)
	}
}

func TestReloginAfterTheTokenIsRefused(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if _, err := c.ReadKV(ctx, "backends"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.token = "s.revoked-or-expired"
	c.mu.Unlock()
	if _, err := c.ReadKV(ctx, "backends"); err != nil {
		t.Fatalf("read after a refused token: %v", err)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
