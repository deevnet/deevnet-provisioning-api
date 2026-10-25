package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/version"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestServer(db Pinger) http.Handler {
	return New(Config{
		Token:  "s3cret",
		DB:     db,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func do(t *testing.T, h http.Handler, method, path, token string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := map[string]string{}
	if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: body is not JSON: %v", method, path, err)
		}
	}
	return rec, body
}

func TestHealthzIgnoresDatabase(t *testing.T) {
	h := newTestServer(fakeDB{err: errors.New("down")})
	rec, body := do(t, h, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("got %d %v, want 200 status=ok", rec.Code, body)
	}
}

func TestReadyz(t *testing.T) {
	rec, body := do(t, newTestServer(fakeDB{}), http.MethodGet, "/readyz", "")
	if rec.Code != http.StatusOK || body["database"] != "ok" {
		t.Fatalf("db up: got %d %v, want 200 database=ok", rec.Code, body)
	}

	rec, body = do(t, newTestServer(fakeDB{err: errors.New("dial tcp 10.0.0.1:5432: refused")}), http.MethodGet, "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable || body["database"] != "unreachable" {
		t.Fatalf("db down: got %d %v, want 503 database=unreachable", rec.Code, body)
	}
	if got := rec.Body.String(); strings.Contains(got, "10.0.0.1") {
		t.Errorf("readiness body leaks the connection error: %s", got)
	}
}

func TestVersion(t *testing.T) {
	rec, body := do(t, newTestServer(fakeDB{}), http.MethodGet, "/version", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body["version"] != version.Version || body["commit"] != version.Commit || body["built"] != version.Built {
		t.Fatalf("body = %v, want the version package values", body)
	}
}

func TestV1RequiresTokenThenNotImplemented(t *testing.T) {
	h := newTestServer(fakeDB{})

	if rec, _ := do(t, h, http.MethodGet, "/v1/devices", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", rec.Code)
	}
	if rec, _ := do(t, h, http.MethodPost, "/v1/devices", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec.Code)
	}
	rec, body := do(t, h, http.MethodGet, "/v1/devices", "s3cret")
	if rec.Code != http.StatusNotImplemented || body["error"] != "not implemented" {
		t.Fatalf("valid token: got %d %v, want 501", rec.Code, body)
	}
}

func TestMethodAndPathRouting(t *testing.T) {
	h := newTestServer(fakeDB{})
	if rec, _ := do(t, h, http.MethodPost, "/healthz", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: status = %d, want 405", rec.Code)
	}
	if rec, _ := do(t, h, http.MethodGet, "/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope: status = %d, want 404", rec.Code)
	}
}

func TestNotMigratedIsNotReady(t *testing.T) {
	h := New(Config{
		Token:    "s3cret",
		DB:       fakeDB{},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Migrated: func() bool { return false },
	})
	rec, body := do(t, h, http.MethodGet, "/readyz", "")
	if rec.Code != http.StatusServiceUnavailable || body["database"] != "migrating" {
		t.Fatalf("readyz: got %d %v, want 503 database=migrating", rec.Code, body)
	}
	if rec, _ := do(t, h, http.MethodGet, "/v1/tenants", "s3cret"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/v1 before migration: %d, want 503", rec.Code)
	}
	if rec, _ := do(t, h, http.MethodGet, "/v1/tenants", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1 without a token before migration: %d, want 401 first", rec.Code)
	}
}

type fakeSecrets string

func (f fakeSecrets) Health(context.Context) string { return string(f) }

// A sealed OpenBao is not ready, and the body says so, so a deploy can tell
// "up, but sealed" from "not up" (ADR-0042 §3).
func TestSealedIsNotReady(t *testing.T) {
	for _, state := range []string{"sealed", "unreachable", "uninitialized"} {
		h := New(Config{Token: "s3cret", DB: fakeDB{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Secrets: fakeSecrets(state)})
		rec, body := do(t, h, http.MethodGet, "/readyz", "")
		if rec.Code != http.StatusServiceUnavailable || body["openbao"] != state || body["database"] != "ok" {
			t.Errorf("%s: got %d %v, want 503 openbao=%s database=ok", state, rec.Code, body, state)
		}
	}
	h := New(Config{Token: "s3cret", DB: fakeDB{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Secrets: fakeSecrets("ok")})
	if rec, body := do(t, h, http.MethodGet, "/readyz", ""); rec.Code != http.StatusOK || body["openbao"] != "ok" {
		t.Errorf("open: got %d %v, want 200 openbao=ok", rec.Code, body)
	}
}

// Started while OpenBao was sealed: /v1 answers 503 until the API has read
// what it needs, and a caller without a token is still told 401 first.
func TestV1WaitsForSecrets(t *testing.T) {
	h := New(Config{
		Token:         "s3cret",
		DB:            fakeDB{},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		SecretsLoaded: func() bool { return false },
	})
	rec, body := do(t, h, http.MethodGet, "/v1/tenants", "s3cret")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body["error"], "sealed") {
		t.Fatalf("/v1 while waiting: %d %v, want 503 naming the seal", rec.Code, body)
	}
	if rec, _ := do(t, h, http.MethodGet, "/v1/tenants", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/v1 without a token while waiting: %d, want 401 first", rec.Code)
	}
}
