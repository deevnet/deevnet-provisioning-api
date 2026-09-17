package tenant

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

// Tenant API tokens carry their tenant's name and a MAC over it, keyed by a
// secret the registry does not hold (ADR-0016 §3 keeps it in OpenBao KV).
//
//	dvt1.<tenant>.<random>.<mac>
//
// That is what lets a tenant restore itself after the registry is lost
// (ADR-0015 §5): the API can still tell a token it issued for that name from
// one somebody made up. The registry's hash of the token is the revocation:
// while a tenant is registered, only the token whose hash it holds is accepted.
const tokenVersion = "dvt1"

// Tokens issues and verifies tenant tokens.
type Tokens struct {
	key []byte
}

// NewTokens takes the MAC key, at least 32 bytes.
func NewTokens(key []byte) (*Tokens, error) {
	if len(key) < 32 {
		return nil, errors.New("tenant token key must be at least 32 bytes")
	}
	return &Tokens{key: append([]byte(nil), key...)}, nil
}

// Issue returns a new token for a tenant.
func (t *Tokens) Issue(name string) (string, error) {
	r := make([]byte, 24)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(r)
	return tokenVersion + "." + name + "." + nonce + "." + t.mac(name, nonce), nil
}

// Verify returns the tenant a token was issued for, if the API issued it.
func (t *Tokens) Verify(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != tokenVersion || !ValidName(parts[1]) || parts[2] == "" {
		return "", false
	}
	want := t.mac(parts[1], parts[2])
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(want)) != 1 {
		return "", false
	}
	return parts[1], true
}

func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

func (t *Tokens) mac(name, nonce string) string {
	m := hmac.New(sha256.New, t.key)
	m.Write([]byte(tokenVersion + "." + name + "." + nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
