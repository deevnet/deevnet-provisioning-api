// Package auth is the API's token check.
//
// It is a stub: one shared bearer token, delivered to the container from the
// vault. ADR-0012 gives each tenant its own credential confined to its scope;
// that replaces this package, and the middleware seam stays where it is.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Bearer admits a request only when its Authorization header carries token.
//
// It panics on an empty token rather than returning a middleware that would
// compare an empty header equal to it and admit everyone.
func Bearer(token string, next http.Handler) http.Handler {
	if token == "" {
		panic("auth: empty bearer token")
	}
	want := []byte(token)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		// Constant time, so response timing does not reveal how much of a
		// guessed token was right.
		if !ok || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="deevnet-api"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
