// Package opnsense ensures the core router's resolver forwards each tenant zone
// to the tenant DNS server (ADR-0004), through the OPNsense API.
//
// The endpoints and payload are the ones the deevnet.net opnsense_dns role
// already drives, verified there against OPNsense: query-forwarding rows live
// behind unbound/settings/{search,add,set,del}Forward, wrapped in a "dot"
// object whose type must be "forward"; a change only reaches the running
// resolver after unbound/service/reconfigure.
package opnsense

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Client is a tenant.Resolver.
type Client struct {
	base        string // https://10.20.25.1/api
	key, secret string
	http        *http.Client
}

// New takes the API root, for example https://10.20.25.1/api. insecureTLS
// accepts the router's self-signed certificate, as the Ansible roles do
// (opnsense_validate_certs: false) until the internal CA exists.
func New(apiURL, key, secret string, insecureTLS bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see comment above
	}
	return &Client{
		base:   strings.TrimRight(apiURL, "/"),
		key:    key,
		secret: secret,
		http:   &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

type forwardRow struct {
	UUID        string `json:"uuid"`
	Enabled     string `json:"enabled"`
	Type        string `json:"type"`
	Domain      string `json:"domain"`
	Server      string `json:"server"`
	Description string `json:"description"`
}

// List returns the resolver's query-forwarding rows, keyed by domain.
func (c *Client) List(ctx context.Context) (map[string]forwardRow, error) {
	var resp struct {
		Rows *[]forwardRow `json:"rows"`
	}
	if err := c.post(ctx, "/unbound/settings/searchForward", map[string]int{"current": 1, "rowCount": 1000}, &resp); err != nil {
		return nil, err
	}
	// A build without this endpoint would reconcile nothing and report success.
	if resp.Rows == nil {
		return nil, fmt.Errorf("searchForward returned no rows collection")
	}
	out := map[string]forwardRow{}
	for _, r := range *resp.Rows {
		// The same model backs DNS-over-TLS rows; only plain forwards are ours.
		if r.Type == "forward" {
			out[r.Domain] = r
		}
	}
	return out, nil
}

type dotWrapper struct {
	Dot dotRow `json:"dot"`
}

type dotRow struct {
	Enabled     string `json:"enabled"`
	Type        string `json:"type"`
	Domain      string `json:"domain"`
	Server      string `json:"server"`
	Description string `json:"description"`
}

type result struct {
	Result      string          `json:"result"`
	Validations json.RawMessage `json:"validations,omitempty"`
}

func (c *Client) Ensure(ctx context.Context, fwds []tenant.Forward) error {
	have, err := c.List(ctx)
	if err != nil {
		return err
	}
	changed := false
	for _, f := range fwds {
		row := dotWrapper{Dot: dotRow{Enabled: "1", Type: "forward", Domain: f.Domain, Server: f.Server, Description: f.Description}}
		cur, ok := have[f.Domain]
		switch {
		case !ok:
			if err := c.write(ctx, "/unbound/settings/addForward", row, "saved"); err != nil {
				return fmt.Errorf("add forward %s: %w", f.Domain, err)
			}
			changed = true
		case cur.Server != f.Server || cur.Enabled != "1":
			// An existing row is adopted as it is, description included, and only
			// corrected where it would send the zone somewhere else.
			row.Dot.Description = cur.Description
			if err := c.write(ctx, "/unbound/settings/setForward/"+cur.UUID, row, "saved"); err != nil {
				return fmt.Errorf("set forward %s: %w", f.Domain, err)
			}
			changed = true
		}
	}
	if changed {
		return c.reconfigure(ctx)
	}
	return nil
}

func (c *Client) Remove(ctx context.Context, domains []string) error {
	have, err := c.List(ctx)
	if err != nil {
		return err
	}
	changed := false
	for _, d := range domains {
		cur, ok := have[d]
		if !ok {
			continue
		}
		var res result
		if err := c.post(ctx, "/unbound/settings/delForward/"+cur.UUID, map[string]string{}, &res); err != nil {
			return fmt.Errorf("delete forward %s: %w", d, err)
		}
		if res.Result != "deleted" && res.Result != "not found" {
			return fmt.Errorf("delete forward %s: result %q", d, res.Result)
		}
		changed = true
	}
	if changed {
		return c.reconfigure(ctx)
	}
	return nil
}

func (c *Client) write(ctx context.Context, path string, body any, want string) error {
	var res result
	if err := c.post(ctx, path, body, &res); err != nil {
		return err
	}
	// OPNsense answers 200 with "result":"failed" on a validation error.
	if res.Result != want {
		return fmt.Errorf("result %q, validations %s", res.Result, string(res.Validations))
	}
	return nil
}

func (c *Client) reconfigure(ctx context.Context) error {
	var res struct {
		Status string `json:"status"`
	}
	if err := c.post(ctx, "/unbound/service/reconfigure", map[string]string{}, &res); err != nil {
		return fmt.Errorf("reconfigure unbound: %w", err)
	}
	if res.Status != "ok" {
		return fmt.Errorf("reconfigure unbound: status %q", res.Status)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		s := strings.TrimSpace(string(body))
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		return fmt.Errorf("POST %s: %d %s", path, resp.StatusCode, s)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("POST %s: decoding response: %w", path, err)
	}
	return nil
}
