// Package proxmox reads which tenant indexes the fabric already carries
// (ADR-0015 §3). It only reads; a token with SDN audit access is enough.
//
// Field names are the ones Proxmox's SDN API uses and bpg/terraform-provider-proxmox
// models: a zone is {"zone", "vrf-vxlan", "pending"}, a VNet is {"vnet", "zone",
// "tag", "pending"}. pending=1 includes changes not yet applied, which already
// claim their numbers.
package proxmox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Client reads the fabric (tenant.Fabric) and builds tenant networks and
// workloads (tenant.Network, tenant.Compute).
type Client struct {
	base string // https://10.20.99.22:8006/api2/json
	auth string
	site tenant.Site
	http *http.Client

	// TaskTimeout bounds a clone, start, stop or delete. Default 10 minutes.
	TaskTimeout time.Duration
}

// New takes the node's API root, for example https://10.20.99.22:8006, and a
// token as user@realm!name and its secret.
func New(apiURL, tokenID, tokenSecret string, site tenant.Site, insecureTLS bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		// Proxmox serves its own self-signed certificate until the internal CA exists.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &Client{
		base: strings.TrimRight(apiURL, "/") + "/api2/json",
		auth: fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret),
		site: site,
		http: &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

// flexInt accepts a number or a numeric string: the PVE API is not consistent
// about which it returns.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

type zoneFields struct {
	VRFVXLAN flexInt `json:"vrf-vxlan"`
}

type zone struct {
	Zone string `json:"zone"`
	zoneFields
	Pending *zoneFields `json:"pending"`
}

type vnetFields struct {
	Zone string  `json:"zone"`
	Tag  flexInt `json:"tag"`
}

type vnet struct {
	VNet string `json:"vnet"`
	vnetFields
	Pending *vnetFields `json:"pending"`
}

func (c *Client) Claims(ctx context.Context) ([]tenant.Claim, error) {
	var zones []zone
	if err := c.get(ctx, "/cluster/sdn/zones?pending=1", &zones); err != nil {
		return nil, err
	}
	var vnets []vnet
	if err := c.get(ctx, "/cluster/sdn/vnets?pending=1", &vnets); err != nil {
		return nil, err
	}
	return claims(c.site, zones, vnets), nil
}

func claims(site tenant.Site, zones []zone, vnets []vnet) []tenant.Claim {
	seen := map[tenant.Claim]bool{}
	var out []tenant.Claim
	add := func(c tenant.Claim) {
		if c.Index != 0 && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, z := range zones {
		add(tenant.Claim{Index: site.IndexForVRFVNI(int(z.VRFVXLAN)), Zone: z.Zone})
		if z.Pending != nil {
			add(tenant.Claim{Index: site.IndexForVRFVNI(int(z.Pending.VRFVXLAN)), Zone: z.Zone})
		}
	}
	for _, v := range vnets {
		add(tenant.Claim{Index: site.IndexForVNetTag(int(v.Tag)), Zone: v.Zone})
		if v.Pending != nil {
			zoneName := v.Pending.Zone
			if zoneName == "" {
				zoneName = v.Zone
			}
			add(tenant.Claim{Index: site.IndexForVNetTag(int(v.Pending.Tag)), Zone: zoneName})
		}
	}
	return out
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.request(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body map[string]string) error {
	return c.request(ctx, http.MethodPost, path, body, nil)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}

// request calls the Proxmox API. Bodies are form-encoded, which is what the
// API takes; out is filled from the response's "data" when it is not nil.
func (c *Client) request(ctx context.Context, method, path string, body map[string]string, out any) error {
	var reader io.Reader
	if body != nil {
		form := url.Values{}
		for k, v := range body {
			form.Set(k, v)
		}
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	// Reading an absent SDN object answers 500 with "does not exist", not 404,
	// so "is it there" has to read the message (checked on PVE 8.4).
	case method == http.MethodGet && resp.StatusCode == http.StatusInternalServerError &&
		strings.Contains(string(raw), "does not exist"):
		return errNotFound
	case resp.StatusCode >= 300:
		// Proxmox puts the reason in the status line and in "errors".
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("%s %s: decoding data: %w", method, path, err)
	}
	return nil
}
