// Package openbao is the API's client for OpenBao (ADR-0016): its backend
// credentials from KV, envelope encryption of tenant secrets with Transit, and
// single-use enrollment tokens with response wrapping.
//
// Plain net/http, not the OpenBao Go module: the API uses five endpoints, and
// the repository keeps its dependencies to what it cannot reasonably write.
// The endpoints and shapes were checked against openbao 2.6.2.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Config is how the API reaches OpenBao and who it is there.
type Config struct {
	Addr     string // https://10.20.25.21:8200
	CAFile   string // the pinned listener certificate
	RoleID   string
	SecretID string

	KVMount    string // deevnet-api
	TransitKey string // tenant-secrets
}

// Client logs in with its AppRole on first use and again when its token
// expires or is refused.
type Client struct {
	cfg  Config
	http *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func New(cfg Config) (*Client, error) {
	if cfg.Addr == "" || cfg.RoleID == "" || cfg.SecretID == "" || cfg.KVMount == "" || cfg.TransitKey == "" {
		return nil, errors.New("openbao: address, AppRole, KV mount and Transit key are required")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("openbao: CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("openbao: CA file holds no certificate")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second, Transport: tr}}, nil
}

// errForbidden is a 403: a token that expired or was revoked.
var errForbidden = errors.New("openbao: permission denied")

func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A token is used until a minute before it lapses.
	if c.token != "" && time.Now().Before(c.expiry.Add(-time.Minute)) {
		return c.token, nil
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	body := map[string]string{"role_id": c.cfg.RoleID, "secret_id": c.cfg.SecretID}
	if err := c.call(ctx, http.MethodPost, "/v1/auth/approle/login", "", nil, body, &out); err != nil {
		return "", fmt.Errorf("openbao: AppRole login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("openbao: AppRole login returned no token")
	}
	c.token = out.Auth.ClientToken
	c.expiry = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
	return c.token, nil
}

func (c *Client) forget() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// do calls OpenBao as the API, logging in again once if the token is refused.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.login(ctx)
		if err != nil {
			return err
		}
		err = c.call(ctx, method, path, tok, nil, in, out)
		if errors.Is(err, errForbidden) && attempt == 0 {
			c.forget()
			continue
		}
		return err
	}
	return errForbidden
}

// ReadKV returns the string fields of a KV v2 secret.
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]string, error) {
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/"+c.cfg.KVMount+"/data/"+path, nil, &out); err != nil {
		return nil, fmt.Errorf("openbao: KV %s: %w", path, err)
	}
	m := make(map[string]string, len(out.Data.Data))
	for k, v := range out.Data.Data {
		if s, ok := v.(string); ok {
			m[k] = s
		}
	}
	return m, nil
}

// CiphertextPrefix marks a Transit ciphertext, so a value stored before
// encryption was turned on can be told apart and read as it is.
const CiphertextPrefix = "vault:v"

// Seal encrypts plaintext with the Transit key.
func (c *Client) Seal(ctx context.Context, plaintext string) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	in := map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte(plaintext))}
	if err := c.do(ctx, http.MethodPost, "/v1/transit/encrypt/"+c.cfg.TransitKey, in, &out); err != nil {
		return "", fmt.Errorf("openbao: encrypt: %w", err)
	}
	return out.Data.Ciphertext, nil
}

// Open decrypts a Transit ciphertext. A value without the ciphertext prefix is
// returned unchanged: it was stored before encryption was on, and is sealed
// the next time it is written.
func (c *Client) Open(ctx context.Context, stored string) (string, error) {
	if !strings.HasPrefix(stored, CiphertextPrefix) {
		return stored, nil
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/transit/decrypt/"+c.cfg.TransitKey, map[string]string{"ciphertext": stored}, &out); err != nil {
		return "", fmt.Errorf("openbao: decrypt: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return "", fmt.Errorf("openbao: decrypt: %w", err)
	}
	return string(raw), nil
}

// Wrap puts data in the cubbyhole of a single-use token that lives for ttl, and
// returns that token (ADR-0016 §4).
func (c *Client) Wrap(ctx context.Context, data map[string]string, ttl time.Duration) (string, time.Time, error) {
	tok, err := c.login(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	var out struct {
		WrapInfo struct {
			Token        string    `json:"token"`
			CreationTime time.Time `json:"creation_time"`
			TTL          int       `json:"ttl"`
		} `json:"wrap_info"`
	}
	hdr := map[string]string{"X-Vault-Wrap-TTL": fmt.Sprintf("%ds", int(ttl.Seconds()))}
	if err := c.call(ctx, http.MethodPost, "/v1/sys/wrapping/wrap", tok, hdr, data, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("openbao: wrap: %w", err)
	}
	if out.WrapInfo.Token == "" {
		return "", time.Time{}, errors.New("openbao: wrap returned no token")
	}
	return out.WrapInfo.Token, out.WrapInfo.CreationTime.Add(time.Duration(out.WrapInfo.TTL) * time.Second), nil
}

// ErrNotRedeemable is a wrapping token that was already spent, expired, or
// never existed. OpenBao does not say which, and neither does the API.
var ErrNotRedeemable = tenant.ErrNotRedeemable

// Unwrap spends a wrapping token and returns what it held. The token itself is
// the credential: no AppRole token is sent.
func (c *Client) Unwrap(ctx context.Context, wrappingToken string) (map[string]string, error) {
	var out struct {
		Data map[string]any `json:"data"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/sys/wrapping/unwrap", wrappingToken, nil, map[string]string{}, &out)
	if err != nil {
		var se *statusError
		if errors.Is(err, errForbidden) || (errors.As(err, &se) && se.code == http.StatusBadRequest) {
			return nil, ErrNotRedeemable
		}
		return nil, fmt.Errorf("openbao: unwrap: %w", err)
	}
	m := map[string]string{}
	for k, v := range out.Data {
		if s, ok := v.(string); ok {
			m[k] = s
		}
	}
	return m, nil
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("status %d: %s", e.code, e.body) }

func (c *Client) call(ctx context.Context, method, path, token string, headers map[string]string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.Addr, "/")+path, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return errForbidden
	case resp.StatusCode >= 300:
		// OpenBao's error bodies name the failure, never a secret.
		s := strings.TrimSpace(string(raw))
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		return &statusError{code: resp.StatusCode, body: s}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decoding %s: %w", path, err)
		}
	}
	return nil
}
