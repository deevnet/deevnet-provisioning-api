package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// controller is a stand-in for the Omada Open API: enough of it to exercise the
// token dance, the errorCode envelope and the profile/key operations.
type controller struct {
	tokens   atomic.Int32 // how many times a token was minted
	expires  int          // expiresIn the token grant reports
	keys     map[string]pskEntry
	profiles []profileBrief
	// rejectToken makes the next authenticated call answer as if the token had
	// lapsed, once.
	rejectToken atomic.Bool
	addCalls    atomic.Int32
	delCalls    atomic.Int32
}

func newController() *controller {
	return &controller{
		keys:     map[string]pskEntry{},
		profiles: []profileBrief{{ID: "p1", ProfileName: "DVNTM-IOT", SSID: []string{"DVNTM-IOT"}}},
	}
}

func (c *controller) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"result": map[string]any{"omadacId": "OMADAC"}})
	})
	mux.HandleFunc("/openapi/authorize/token", func(w http.ResponseWriter, _ *http.Request) {
		c.tokens.Add(1)
		writeJSON(w, map[string]any{"errorCode": 0, "result": map[string]any{
			"accessToken": "tok", "expiresIn": c.expires,
		}})
	})
	mux.HandleFunc("/openapi/v1/OMADAC/", func(w http.ResponseWriter, r *http.Request) {
		if c.rejectToken.CompareAndSwap(true, false) {
			writeJSON(w, map[string]any{"errorCode": -44112, "msg": "token invalid"})
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/openapi/v1/OMADAC")
		switch {
		case path == "/sites":
			writeJSON(w, map[string]any{"errorCode": 0, "result": map[string]any{
				"data": []map[string]string{{"siteId": "S1", "name": "Default"}},
			}})
		case path == "/sites/S1/ppsk-profiles":
			writeJSON(w, map[string]any{"errorCode": 0, "result": c.profiles})
		case path == "/sites/S1/ppsk-profile/p1":
			out := []pskEntry{}
			for _, e := range c.keys {
				out = append(out, e)
			}
			writeJSON(w, map[string]any{"errorCode": 0, "result": map[string]any{"ppsk": out}})
		case path == "/sites/S1/ppsk-profile/p1/add-psk":
			c.addCalls.Add(1)
			var body struct {
				PPSKList []pskEntry `json:"ppskList"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, e := range body.PPSKList {
				c.keys[e.Name] = e
			}
			writeJSON(w, map[string]any{"errorCode": 0})
		case path == "/sites/S1/ppsk-profile/p1/delete-psk":
			c.delCalls.Add(1)
			var body struct {
				Names []string `json:"ppskNameList"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, n := range body.Names {
				delete(c.keys, n)
			}
			writeJSON(w, map[string]any{"errorCode": 0})
		default:
			writeJSON(w, map[string]any{"errorCode": -1, "msg": "no such thing"})
		}
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newClient(t *testing.T, c *controller) *Client {
	t.Helper()
	srv := httptest.NewServer(c.handler(t))
	t.Cleanup(srv.Close)
	return New(srv.URL, "id", "secret", false)
}

func spec() tenant.WiFiKeySpec {
	return tenant.WiFiKeySpec{SSID: "DVNTM-IOT", Name: "eds-devices", PSK: "aPasswordLongEnough", VLAN: 30}
}

func TestEnsureKeyWritesItWithItsVLAN(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	if err := cl.EnsureKey(context.Background(), spec()); err != nil {
		t.Fatal(err)
	}
	got, ok := c.keys["eds-devices"]
	if !ok || got.VLAN != 30 || got.PSK != "aPasswordLongEnough" {
		t.Fatalf("controller has %+v (ok=%v)", got, ok)
	}
}

// Re-ensuring an identical key must not touch the controller: an add/delete
// cycle would drop every device holding it for the duration.
func TestEnsureKeyIsANoOpWhenAlreadyRight(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	ctx := context.Background()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	adds, dels := c.addCalls.Load(), c.delCalls.Load()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	if c.addCalls.Load() != adds || c.delCalls.Load() != dels {
		t.Errorf("a converged key was rewritten: adds %d->%d dels %d->%d",
			adds, c.addCalls.Load(), dels, c.delCalls.Load())
	}
}

// A key whose password or VLAN differs is corrected, which the controller has
// no single operation for.
func TestEnsureKeyCorrectsADifferentOne(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	ctx := context.Background()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	changed := spec()
	changed.PSK = "aDifferentPassword"
	if err := cl.EnsureKey(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if c.keys["eds-devices"].PSK != "aDifferentPassword" {
		t.Errorf("key = %+v", c.keys["eds-devices"])
	}
	if c.delCalls.Load() != 1 {
		t.Errorf("delete calls = %d, want 1", c.delCalls.Load())
	}
}

func TestRemoveKeyIsIdempotent(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	ctx := context.Background()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := cl.RemoveKey(ctx, "DVNTM-IOT", "eds-devices"); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
	}
	if len(c.keys) != 0 {
		t.Errorf("keys left: %v", c.keys)
	}
}

// The token is cached, so a second operation does not re-authenticate.
func TestTokenIsReused(t *testing.T) {
	c := newController()
	c.expires = 3600
	cl := newClient(t, c)
	ctx := context.Background()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	if n := c.tokens.Load(); n != 1 {
		t.Errorf("minted %d tokens, want 1", n)
	}
}

// A token the controller no longer accepts is replaced once, and the call
// succeeds - this is the failure that would otherwise only appear at a TTL
// boundary, long after deployment.
func TestLapsedTokenIsRetriedExactlyOnce(t *testing.T) {
	c := newController()
	c.expires = 3600
	cl := newClient(t, c)
	ctx := context.Background()
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	c.rejectToken.Store(true)
	if err := cl.EnsureKey(ctx, spec()); err != nil {
		t.Fatalf("a lapsed token should have been replaced: %v", err)
	}
	if n := c.tokens.Load(); n != 2 {
		t.Errorf("minted %d tokens, want 2", n)
	}
}

// An expiresIn the controller does not give must not mean "never expires".
func TestMissingExpiryFallsBackToAShortTTL(t *testing.T) {
	c := newController()
	c.expires = 0
	cl := newClient(t, c)
	if _, err := cl.auth(context.Background()); err != nil {
		t.Fatal(err)
	}
	cl.mu.Lock()
	exp := cl.tokenExp
	cl.mu.Unlock()
	if exp.IsZero() {
		t.Fatal("no expiry was set")
	}
}

// HTTP 200 with a non-zero errorCode is a failure, not a success.
func TestErrorCodeOnHTTP200IsAFailure(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	err := cl.EnsureKey(context.Background(), tenant.WiFiKeySpec{
		SSID: "NOT-A-REAL-SSID", Name: "eds-devices", PSK: "aPasswordLongEnough", VLAN: 30,
	})
	if err == nil {
		t.Fatal("a missing profile was treated as success")
	}
	if !strings.Contains(err.Error(), "NOT-A-REAL-SSID") {
		t.Errorf("err = %v, should name the SSID", err)
	}
}

// Bad input is refused before anything is sent, so the controller never sees a
// key it would reject.
func TestInvalidSpecIsRefusedLocally(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		s    tenant.WiFiKeySpec
	}{
		{"short psk", tenant.WiFiKeySpec{SSID: "DVNTM-IOT", Name: "n", PSK: "short", VLAN: 30}},
		{"no name", tenant.WiFiKeySpec{SSID: "DVNTM-IOT", Name: "", PSK: "aPasswordLongEnough", VLAN: 30}},
		{"vlan out of range", tenant.WiFiKeySpec{SSID: "DVNTM-IOT", Name: "n", PSK: "aPasswordLongEnough", VLAN: 9999}},
	} {
		if err := cl.EnsureKey(ctx, tc.s); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	if c.tokens.Load() != 0 {
		t.Error("a refused spec still reached the controller")
	}
}

// An error must not carry the request body: it holds a tenant's password.
func TestErrorsDoNotCarryTheRequestBody(t *testing.T) {
	c := newController()
	cl := newClient(t, c)
	err := cl.EnsureKey(context.Background(), tenant.WiFiKeySpec{
		SSID: "NOT-A-REAL-SSID", Name: "eds-devices", PSK: "sup3rSecretPassword", VLAN: 30,
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "sup3rSecretPassword") {
		t.Fatalf("the psk leaked into an error: %v", err)
	}
}
