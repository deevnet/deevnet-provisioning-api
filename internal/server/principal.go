package server

import (
	"context"
	"net/http"

	"github.com/deevnet/deevnet-provisioning-api/internal/auth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// principal is who a /v1 request speaks for.
type principal struct {
	operator bool
	// tenant is set when the token is a tenant token the API issued. registered
	// is false for a tenant restoring itself after the registry was lost.
	tenant     string
	registered bool
	// presented is a token that is neither of the above. The only thing it can
	// do is create the tenant an enrollment token was issued for.
	presented string
}

type principalKey struct{}

func principalFrom(ctx context.Context) principal {
	p, _ := ctx.Value(principalKey{}).(principal)
	return p
}

// requireToken refuses a request with no bearer token at all, before anything
// touches the database.
func requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.Token(r); !ok {
			auth.Deny(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// identify resolves the token to a principal.
func identify(operatorToken string, tenants *tenant.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := auth.Token(r)
		var p principal
		switch {
		case auth.Equal(tok, operatorToken):
			p.operator = true
		case tenants != nil:
			if c, ok := tenants.Authenticate(r.Context(), tok); ok {
				p.tenant, p.registered = c.Tenant, c.Registered
			} else {
				p.presented = tok
			}
		default:
			p.presented = tok
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// operatorOnly admits the operator and refuses everyone else: 401 for a token
// the API does not recognise, 403 for a tenant.
func operatorOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		switch {
		case p.operator:
			next(w, r)
		case p.tenant != "":
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "operator only"})
		default:
			auth.Deny(w)
		}
	}
}

// knownCaller admits the operator and registered tenants.
func knownCaller(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		if p.operator || (p.tenant != "" && p.registered) {
			next(w, r)
			return
		}
		auth.Deny(w)
	}
}
