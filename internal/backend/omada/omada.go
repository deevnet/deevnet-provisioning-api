// Package omada issues per-tenant PPSK keys into the wireless controller's
// profiles, through its documented Open API (ADR-0009, ADR-0012 §6).
//
// Inventory owns the SSID and the profile; this owns the keys inside the
// profile, one per tenant per trust class. The VLAN is bound to the key, which
// is what decides where a device lands - proven on the site's EAP650-Outdoor at
// firmware 1.3.11 in CHG-0005 phase 6.
//
// Behaviour relied on here was read from the spec controller 6.3.0.45 serves at
// /v3/api-docs/00 All, and matches what CHG-0005 found on the wire:
//
//   - Every response carries an errorCode, and a failure still arrives as HTTP
//     200. A 200 is not success.
//   - getPPSKProfiles returns each profile with the SSIDs bound to it, so a
//     profile is resolved from an SSID name in one call. The SSID list does NOT
//     carry ppskProfileId, so it is no use for this.
//   - getPPSKProfileDetail returns the keys, including their passwords in
//     plaintext. That is what makes read-before-write possible here.
//   - delete-psk takes key NAMES, not ids.
//   - A key's psk must be 8 to 63 visible ASCII characters, and its name 1 to 64.
//
// Unlike every other backend, the credential here expires: the token is a
// client-credentials grant with a TTL, so it is cached and re-fetched. There is
// deliberately no refresh path - re-authenticating is a single call, and a
// refresh branch would only ever run at a TTL boundary, which is the code least
// likely to be exercised and most likely to be wrong.
package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// defaultTokenTTL is used when the controller does not say how long a token
// lasts. Short and cheap: re-authenticating costs one call.
const defaultTokenTTL = 10 * time.Minute

// tokenSkew re-authenticates this far before expiry, so a token cannot lapse
// between the check and the call that uses it.
const tokenSkew = 60 * time.Second

// Client is a tenant.Wireless.
type Client struct {
	base       string // https://10.20.99.40:8043
	id, secret string
	http       *http.Client

	mu       sync.Mutex
	omadacID string
	siteID   string
	token    string
	tokenExp time.Time
}

// New takes the controller root, for example https://10.20.99.40:8043.
// insecureTLS accepts the controller's own certificate, as the Ansible play
// does (validate_certs: false), until it is issued one from the site CA.
func New(apiURL, clientID, clientSecret string, insecureTLS bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see comment above
	}
	return &Client{
		base:   strings.TrimRight(apiURL, "/"),
		id:     clientID,
		secret: clientSecret,
		http:   &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// APIError is a controller refusal: HTTP 200 with a non-zero errorCode.
//
// It carries the code and the controller's message and never the request body,
// because a request body here contains a tenant's PSK and errors are logged and
// returned to callers.
type APIError struct {
	Code int
	Msg  string
	Op   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("omada %s: errorCode %d (%s)", e.Op, e.Code, e.Msg)
}

// errInvalidToken is the controller's "your token is no longer good" family.
// The codes are not documented, so a 401 is treated the same way.
func isAuthFailure(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == -44112 || apiErr.Code == -44113 || apiErr.Code == -1200
	}
	return errors.Is(err, errUnauthorized)
}

var errUnauthorized = errors.New("unauthorized")

type envelope struct {
	ErrorCode int             `json:"errorCode"`
	Msg       string          `json:"msg"`
	Result    json.RawMessage `json:"result"`
}

// ---------------------------------------------------------------- identity

// identity fetches the controller id, which every Open API path needs and which
// is only available before a token exists.
func (c *Client) identity(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.omadacID != "" {
		id := c.omadacID
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	var out struct {
		Result struct {
			OmadacID string `json:"omadacId"`
		} `json:"result"`
	}
	// omada-api: UNDOCUMENTED /api/info tested-on 6.3.0.45
	// Unauthenticated, and the only source of omadacId before a token exists.
	// Marked so ADR-0009's upgrade sweep finds it here as well as in the play.
	if err := c.raw(ctx, http.MethodGet, "/api/info", nil, &out); err != nil {
		return "", fmt.Errorf("reading controller identity: %w", err)
	}
	if out.Result.OmadacID == "" {
		return "", errors.New("controller returned no omadacId")
	}
	c.mu.Lock()
	c.omadacID = out.Result.OmadacID
	c.mu.Unlock()
	return out.Result.OmadacID, nil
}

// auth returns a usable access token, fetching one if the cached token is
// missing or close to expiry.
func (c *Client) auth(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	id, err := c.identity(ctx)
	if err != nil {
		return "", err
	}
	body := map[string]string{"omadacId": id, "client_id": c.id, "client_secret": c.secret}
	var out struct {
		ErrorCode int    `json:"errorCode"`
		Msg       string `json:"msg"`
		Result    struct {
			AccessToken string `json:"accessToken"`
			ExpiresIn   int    `json:"expiresIn"`
		} `json:"result"`
	}
	// omada-api: documented authorize/token (TP-Link Open API guide; not in the served spec) spec 6.3.0.45
	if err := c.raw(ctx, http.MethodPost, "/openapi/authorize/token?grant_type=client_credentials", body, &out); err != nil {
		return "", fmt.Errorf("authenticating: %w", err)
	}
	if out.ErrorCode != 0 || out.Result.AccessToken == "" {
		return "", &APIError{Code: out.ErrorCode, Msg: out.Msg, Op: "authorize/token"}
	}
	ttl := defaultTokenTTL
	if out.Result.ExpiresIn > 0 {
		ttl = time.Duration(out.Result.ExpiresIn) * time.Second
	}
	if ttl > tokenSkew {
		ttl -= tokenSkew
	}
	c.mu.Lock()
	c.token, c.tokenExp = out.Result.AccessToken, time.Now().Add(ttl)
	c.mu.Unlock()
	return out.Result.AccessToken, nil
}

// site resolves the one site this controller serves. More than one is refused:
// the API serves a single site (ADR-0015 §8), and picking one silently would be
// a good way to write a tenant's key into the wrong place.
func (c *Client) site(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.siteID != "" {
		id := c.siteID
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	var out struct {
		Data []struct {
			SiteID string `json:"siteId"`
			Name   string `json:"name"`
		} `json:"data"`
	}
	// omada-api: documented getSiteList spec 6.3.0.45
	if err := c.call(ctx, http.MethodGet, "/sites?page=1&pageSize=100", nil, &out); err != nil {
		return "", err
	}
	if len(out.Data) != 1 {
		return "", fmt.Errorf("controller serves %d sites, expected exactly 1", len(out.Data))
	}
	c.mu.Lock()
	c.siteID = out.Data[0].SiteID
	c.mu.Unlock()
	return out.Data[0].SiteID, nil
}

// ---------------------------------------------------------------- profiles

type profileBrief struct {
	ID          string   `json:"id"`
	ProfileName string   `json:"profileName"`
	SSID        []string `json:"ssid"`
}

type pskEntry struct {
	Name string `json:"name"`
	PSK  string `json:"psk"`
	MAC  string `json:"mac,omitempty"`
	VLAN int    `json:"vlan,omitempty"`
}

// profileForSSID finds the PPSK profile bound to ssid.
//
// getPPSKProfiles reports the SSIDs bound to each profile, so this is one call.
// Resolving through the SSID rather than through a configured profile name is
// deliberate: the SSID is the thing a tenant is told to join, and it keeps the
// API from having to agree with Ansible inventory about a profile's name.
func (c *Client) profileForSSID(ctx context.Context, siteID, ssid string) (profileBrief, error) {
	var profiles []profileBrief
	// omada-api: documented getPPSKProfiles spec 6.3.0.45
	if err := c.call(ctx, http.MethodGet, "/sites/"+siteID+"/ppsk-profiles", nil, &profiles); err != nil {
		return profileBrief{}, err
	}
	for _, p := range profiles {
		for _, s := range p.SSID {
			if s == ssid {
				return p, nil
			}
		}
	}
	return profileBrief{}, fmt.Errorf("no PPSK profile is bound to SSID %q; inventory creates it (ADR-0012 §6)", ssid)
}

// keysIn returns the keys a profile holds.
//
// The response contains every tenant's PSK in plaintext. It is used to decide
// whether a write is needed and is never logged or returned.
func (c *Client) keysIn(ctx context.Context, siteID, profileID string) ([]pskEntry, error) {
	var out struct {
		PPSK []pskEntry `json:"ppsk"`
	}
	// omada-api: documented getPPSKProfileDetail spec 6.3.0.45
	if err := c.call(ctx, http.MethodGet, "/sites/"+siteID+"/ppsk-profile/"+profileID, nil, &out); err != nil {
		return nil, err
	}
	return out.PPSK, nil
}

// EnsureKey makes k exist in its SSID's profile, with that PSK and VLAN.
func (c *Client) EnsureKey(ctx context.Context, k tenant.WiFiKeySpec) error {
	if !tenant.ValidPSK(k.PSK) {
		return errors.New("psk must be 8 to 63 visible ASCII characters")
	}
	if k.Name == "" || len(k.Name) > 64 {
		return errors.New("key name must be 1 to 64 characters")
	}
	if k.VLAN < 1 || k.VLAN > 4094 {
		return fmt.Errorf("vlan %d is outside 1-4094", k.VLAN)
	}
	siteID, err := c.site(ctx)
	if err != nil {
		return err
	}
	profile, err := c.profileForSSID(ctx, siteID, k.SSID)
	if err != nil {
		return err
	}
	existing, err := c.keysIn(ctx, siteID, profile.ID)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Name != k.Name {
			continue
		}
		if e.PSK == k.PSK && e.VLAN == k.VLAN {
			return nil // already right
		}
		// The controller has no modify-one-key operation, so a correction is a
		// delete and an add. This is the only moment the key is absent, and it
		// happens only when it was already wrong.
		if err := c.deleteKeys(ctx, siteID, profile.ID, k.Name); err != nil {
			return err
		}
		break
	}
	return c.addKey(ctx, siteID, profile.ID, pskEntry{Name: k.Name, PSK: k.PSK, VLAN: k.VLAN})
}

// RemoveKey deletes the key. One that is not there is not an error, so a
// repeated delete converges.
func (c *Client) RemoveKey(ctx context.Context, ssid, name string) error {
	siteID, err := c.site(ctx)
	if err != nil {
		return err
	}
	profile, err := c.profileForSSID(ctx, siteID, ssid)
	if err != nil {
		return err
	}
	existing, err := c.keysIn(ctx, siteID, profile.ID)
	if err != nil {
		return err
	}
	for _, e := range existing {
		if e.Name == name {
			return c.deleteKeys(ctx, siteID, profile.ID, name)
		}
	}
	return nil
}

func (c *Client) addKey(ctx context.Context, siteID, profileID string, e pskEntry) error {
	body := map[string]any{"ppskList": []pskEntry{e}}
	// omada-api: documented addPSKsToPPSKProfile spec 6.3.0.45
	return c.call(ctx, http.MethodPost, "/sites/"+siteID+"/ppsk-profile/"+profileID+"/add-psk", body, nil)
}

func (c *Client) deleteKeys(ctx context.Context, siteID, profileID string, names ...string) error {
	body := map[string]any{"ppskNameList": names}
	// omada-api: documented deletePSKsToPPSKProfile spec 6.3.0.45
	return c.call(ctx, http.MethodPost, "/sites/"+siteID+"/ppsk-profile/"+profileID+"/delete-psk", body, nil)
}

// ---------------------------------------------------------------- transport

// call makes an authenticated Open API request and unwraps the envelope. It
// retries once, and only once, when the token turns out to be no longer good.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	err := c.callOnce(ctx, method, path, in, out)
	if err != nil && isAuthFailure(err) {
		c.mu.Lock()
		c.token, c.tokenExp = "", time.Time{}
		c.mu.Unlock()
		return c.callOnce(ctx, method, path, in, out)
	}
	return err
}

func (c *Client) callOnce(ctx context.Context, method, path string, in, out any) error {
	id, err := c.identity(ctx)
	if err != nil {
		return err
	}
	token, err := c.auth(ctx)
	if err != nil {
		return err
	}
	var env envelope
	full := "/openapi/v1/" + id + path
	if err := c.do(ctx, method, full, in, &env, token); err != nil {
		return err
	}
	if env.ErrorCode != 0 {
		return &APIError{Code: env.ErrorCode, Msg: env.Msg, Op: method + " " + path}
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("omada %s %s: decoding result: %w", method, path, err)
	}
	return nil
}

// raw is an unenveloped request: the identity read and the token grant, which
// are not under /openapi/v1/{omadacId}.
func (c *Client) raw(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, method, path, in, out, "")
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, token string) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "AccessToken="+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		// The response body is not included: on this API it can echo the
		// request, and a request here carries a tenant's PSK.
		return fmt.Errorf("omada %s %s: HTTP %d", method, redact(path), resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("omada %s %s: decoding response: %w", method, redact(path), err)
	}
	return nil
}

// redact keeps the controller id out of messages that reach a tenant.
func redact(path string) string {
	if !strings.HasPrefix(path, "/openapi/v1/") {
		return path
	}
	rest := strings.TrimPrefix(path, "/openapi/v1/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return "/openapi/v1/-" + rest[i:]
	}
	return "/openapi/v1/-"
}
