package openbao

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// twoKeys is a Transit with an old key and a new one. A ciphertext names the
// key that made it, as Transit's do not, so the stub can refuse the wrong one
// the way Transit does: 400.
func twoKeys(t *testing.T, sealed *bool) *Client {
	t.Helper()
	c, _ := stubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if *sealed {
			sealedHandler(w, r)
			return
		}
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			w.Write([]byte(`{"auth":{"client_token":"t","lease_duration":3600}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/transit/encrypt/")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "vault:v1:" + key + ":" + in["plaintext"]}})
		case strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/transit/decrypt/")
			rest, ok := strings.CutPrefix(in["ciphertext"], "vault:v1:"+key+":")
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":["cipher: message authentication failed"]}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": rest}})
		default:
			http.NotFound(w, r)
		}
	})
	c.cfg.TransitKey, c.cfg.TransitKeyPrevious = "new", "old"
	return c
}

func sealedHandler(w http.ResponseWriter, r *http.Request) { sealed(w, r) }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestOpenFallsBackToThePreviousKey(t *testing.T) {
	no := false
	c := twoKeys(t, &no)
	ctx := context.Background()
	for _, ct := range []string{"vault:v1:new:" + b64("a"), "vault:v1:old:" + b64("a")} {
		if got, err := c.Open(ctx, ct); err != nil || got != "a" {
			t.Errorf("open %s = %q %v, want a", ct, got, err)
		}
	}
	if _, err := c.Open(ctx, "vault:v1:gone:"+b64("a")); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("a ciphertext neither key opens: %v, want a refusal", err)
	}
	c.cfg.TransitKeyPrevious = ""
	if _, err := c.Open(ctx, "vault:v1:old:"+b64("a")); err == nil {
		t.Error("without a previous key, the old key's ciphertext must not open")
	}
}

func TestResealMovesOnlyWhatIsNotCurrent(t *testing.T) {
	no := false
	c := twoKeys(t, &no)
	ctx := context.Background()
	cur := "vault:v1:new:" + b64("a")
	if got, changed, err := c.Reseal(ctx, cur); err != nil || changed || got != cur {
		t.Errorf("current: %q %v %v, want it unchanged", got, changed, err)
	}
	if got, changed, err := c.Reseal(ctx, "vault:v1:old:"+b64("b")); err != nil || !changed || got != "vault:v1:new:"+b64("b") {
		t.Errorf("previous: %q %v %v, want it under the new key", got, changed, err)
	}
	if got, changed, err := c.Reseal(ctx, "plain"); err != nil || !changed || got != "vault:v1:new:"+b64("plain") {
		t.Errorf("plaintext: %q %v %v, want it sealed", got, changed, err)
	}
	if _, _, err := c.Reseal(ctx, "vault:v1:gone:"+b64("c")); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("neither key: %v, want a refusal", err)
	}
	if got, changed, err := c.Reseal(ctx, ""); err != nil || changed || got != "" {
		t.Errorf("empty: %q %v %v", got, changed, err)
	}
}

// Sealed is not a refusal: the previous key is not tried, and nothing moves.
func TestResealStopsWhenSealed(t *testing.T) {
	yes := true
	c := twoKeys(t, &yes)
	if _, _, err := c.Reseal(context.Background(), "vault:v1:old:"+b64("b")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reseal while sealed: %v, want ErrUnavailable", err)
	}
}
