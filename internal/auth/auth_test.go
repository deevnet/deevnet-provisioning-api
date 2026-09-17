package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToken(t *testing.T) {
	for header, want := range map[string]string{
		"":              "",
		"Bearer s3cret": "s3cret",
		"Bearer ":       "",
		"Basic s3cret":  "",
		"s3cret":        "",
	} {
		r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		got, ok := Token(r)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v, want %q", header, got, ok, want)
		}
	}
}

func TestEqual(t *testing.T) {
	if !Equal("s3cret", "s3cret") || Equal("s3cre", "s3cret") || Equal("", "") || Equal("x", "") {
		t.Fatal("Equal")
	}
}

func TestDeny(t *testing.T) {
	rec := httptest.NewRecorder()
	Deny(rec)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
}
