// Package auth reads bearer tokens. Who a token speaks for - the operator, a
// tenant, or an enrollment - is decided by the server (ADR-0015 §10).
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Token returns the bearer token a request carries.
func Token(r *http.Request) (string, bool) {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return "", false
	}
	return got, true
}

// Equal compares a presented token with a known one in constant time, so
// response timing does not reveal how much of a guess was right. An empty
// known token matches nothing.
func Equal(presented, known string) bool {
	if known == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(known)) == 1
}

// Deny answers 401.
func Deny(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="deevnet-api"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
}
