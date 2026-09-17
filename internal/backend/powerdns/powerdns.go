// Package powerdns ensures a tenant's zones, TSIG key and update policy through
// the PowerDNS Authoritative HTTP API (ADR-0004, ADR-0005, ADR-0015 §6).
//
// Behaviour relied on here was checked against pdns-auth 4.9.17:
//   - creating an existing zone or TSIG key answers 409
//   - PUT on a TSIG key replaces its secret
//   - PUT .../metadata/<kind> sets TSIG-ALLOW-DNSUPDATE and ALLOW-DNSUPDATE-FROM
//   - a zone created with "nameservers" gets that apex NS, and default-soa-content
//     supplies the SOA
package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

const apexTTL = 3600

// Client is a tenant.DNS.
type Client struct {
	base string // http://host:8081/api/v1/servers/localhost
	key  string
	http *http.Client
}

// New takes the server's API root, for example http://10.20.25.21:8081.
func New(apiURL, key string) *Client {
	return &Client{
		base: strings.TrimRight(apiURL, "/") + "/api/v1/servers/localhost",
		key:  key,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

var errNotFound = errors.New("not found")

func fqdn(name string) string { return strings.TrimSuffix(name, ".") + "." }

func (c *Client) Ensure(ctx context.Context, t tenant.DNSTenant) error {
	if err := c.ensureKey(ctx, t); err != nil {
		return fmt.Errorf("tsig key %s: %w", t.KeyName, err)
	}
	for _, z := range t.Zones {
		if err := c.ensureZone(ctx, z, t); err != nil {
			return fmt.Errorf("zone %s: %w", z, err)
		}
	}
	return nil
}

func (c *Client) Remove(ctx context.Context, t tenant.DNSTenant) error {
	for _, z := range t.Zones {
		if err := c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(fqdn(z)), nil, nil); err != nil && !errors.Is(err, errNotFound) {
			return fmt.Errorf("delete zone %s: %w", z, err)
		}
	}
	if err := c.do(ctx, http.MethodDelete, "/tsigkeys/"+url.PathEscape(fqdn(t.KeyName)), nil, nil); err != nil && !errors.Is(err, errNotFound) {
		return fmt.Errorf("delete tsig key %s: %w", t.KeyName, err)
	}
	return nil
}

type tsigKey struct {
	Name      string `json:"name,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Key       string `json:"key,omitempty"`
}

func (c *Client) ensureKey(ctx context.Context, t tenant.DNSTenant) error {
	var have tsigKey
	err := c.do(ctx, http.MethodGet, "/tsigkeys/"+url.PathEscape(fqdn(t.KeyName)), nil, &have)
	switch {
	case errors.Is(err, errNotFound):
		return c.do(ctx, http.MethodPost, "/tsigkeys", tsigKey{Name: t.KeyName, Algorithm: t.Algorithm, Key: t.Secret}, nil)
	case err != nil:
		return err
	}
	if have.Key == t.Secret && strings.TrimSuffix(have.Algorithm, ".") == t.Algorithm {
		return nil
	}
	// The tenant's state holds the authoritative secret (ADR-0015 §4).
	return c.do(ctx, http.MethodPut, "/tsigkeys/"+url.PathEscape(fqdn(t.KeyName)), tsigKey{Algorithm: t.Algorithm, Key: t.Secret}, nil)
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type rrset struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl,omitempty"`
	ChangeType string   `json:"changetype,omitempty"`
	Records    []record `json:"records"`
}

type zone struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	RRsets      []rrset  `json:"rrsets,omitempty"`
}

func (c *Client) ensureZone(ctx context.Context, name string, t tenant.DNSTenant) error {
	id := url.PathEscape(fqdn(name))
	apexNS := fqdn(t.ApexNS)

	var have zone
	err := c.do(ctx, http.MethodGet, "/zones/"+id, nil, &have)
	switch {
	case errors.Is(err, errNotFound):
		err = c.do(ctx, http.MethodPost, "/zones", zone{Name: fqdn(name), Kind: "Native", Nameservers: []string{apexNS}}, &have)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	}

	if err := c.ensureApex(ctx, id, fqdn(name), apexNS, have); err != nil {
		return err
	}
	if err := c.purgeIfHandedOver(ctx, id, fqdn(name), t.KeyName, have); err != nil {
		return err
	}
	if err := c.ensureMeta(ctx, id, "TSIG-ALLOW-DNSUPDATE", []string{t.KeyName}); err != nil {
		return err
	}
	return c.ensureMeta(ctx, id, "ALLOW-DNSUPDATE-FROM", t.UpdateFrom)
}

// ensureApex is ADR-0005: the apex SOA primary and the apex NS set are the
// substrate's. A zone created before default-soa-content was set carries the
// placeholder primary `a.misconfigured.dns.server.invalid`. NS records below the
// apex are the tenant's and are never touched.
func (c *Client) ensureApex(ctx context.Context, id, apex, apexNS string, z zone) error {
	var changes []rrset
	for _, rr := range z.RRsets {
		if rr.Name != apex {
			continue
		}
		switch rr.Type {
		case "SOA":
			if len(rr.Records) != 1 {
				continue
			}
			f := strings.Fields(rr.Records[0].Content)
			if len(f) != 7 || f[0] == apexNS {
				continue
			}
			serial, err := strconv.ParseUint(f[2], 10, 32)
			if err != nil {
				return fmt.Errorf("apex SOA serial %q: %w", f[2], err)
			}
			f[0] = apexNS
			// Carried forward and bumped, never reset: a secondary compares serials.
			f[2] = strconv.FormatUint(serial+1, 10)
			changes = append(changes, rrset{Name: apex, Type: "SOA", TTL: ttlOr(rr.TTL), ChangeType: "REPLACE",
				Records: []record{{Content: strings.Join(f, " ")}}})
		case "NS":
			if len(rr.Records) == 1 && rr.Records[0].Content == apexNS {
				continue
			}
			changes = append(changes, rrset{Name: apex, Type: "NS", TTL: ttlOr(rr.TTL), ChangeType: "REPLACE",
				Records: []record{{Content: apexNS}}})
		}
	}
	hasNS := slices.ContainsFunc(z.RRsets, func(rr rrset) bool { return rr.Name == apex && rr.Type == "NS" })
	if !hasNS {
		changes = append(changes, rrset{Name: apex, Type: "NS", TTL: apexTTL, ChangeType: "REPLACE",
			Records: []record{{Content: apexNS}}})
	}
	if len(changes) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPatch, "/zones/"+id, map[string]any{"rrsets": changes}, nil)
}

// purgeIfHandedOver empties a zone that another tenant's key was bound to. A
// reverse zone follows the index, and an index can pass to a new tenant after
// the registry is lost (ADR-0015 §5); the new tenant must not inherit the old
// one's PTR records. Only the apex SOA and NS, which are the substrate's, stay.
// A zone bound to this tenant's own key, or to none, keeps its records: that is
// the tenant itself, or a zone the API is adopting.
func (c *Client) purgeIfHandedOver(ctx context.Context, id, apex, keyName string, z zone) error {
	var bound metadata
	if err := c.do(ctx, http.MethodGet, "/zones/"+id+"/metadata/TSIG-ALLOW-DNSUPDATE", nil, &bound); err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	if len(bound.Metadata) == 0 || sameSet(bound.Metadata, []string{keyName}) {
		return nil
	}
	var deletes []rrset
	for _, rr := range z.RRsets {
		if rr.Name == apex && (rr.Type == "SOA" || rr.Type == "NS") {
			continue
		}
		deletes = append(deletes, rrset{Name: rr.Name, Type: rr.Type, ChangeType: "DELETE", Records: []record{}})
	}
	if len(deletes) == 0 {
		return nil
	}
	return c.do(ctx, http.MethodPatch, "/zones/"+id, map[string]any{"rrsets": deletes}, nil)
}

func ttlOr(ttl int) int {
	if ttl <= 0 {
		return apexTTL
	}
	return ttl
}

type metadata struct {
	Kind     string   `json:"kind,omitempty"`
	Metadata []string `json:"metadata"`
}

func (c *Client) ensureMeta(ctx context.Context, id, kind string, want []string) error {
	path := "/zones/" + id + "/metadata/" + kind
	var have metadata
	if err := c.do(ctx, http.MethodGet, path, nil, &have); err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	if sameSet(have.Metadata, want) {
		return nil
	}
	return c.do(ctx, http.MethodPut, path, metadata{Metadata: want}, nil)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
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
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Accept", "application/json")
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
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode >= 300:
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, snippet(raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}

// snippet keeps an error readable in a log without echoing a whole body. PowerDNS
// error bodies are short JSON; a TSIG key body is never read on an error path.
func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// --- Records (ADR-0015 §13) --------------------------------------------------
//
// The API publishes a workload's own name and the names a tenant adds beside
// them. It touches only those names: everything else in the zone is the
// tenant's, written over RFC 2136 with its own key.

const recordTTL = 300

// EnsureRecords writes an A record in the tenant's zone and the matching PTR in
// its reverse zone.
func (c *Client) EnsureRecords(ctx context.Context, zone, reverseZone string, recs []tenant.DNSRecord) error {
	return c.records(ctx, zone, reverseZone, recs, "REPLACE")
}

// RemoveRecords deletes those names. An absent name is not an error: PowerDNS
// accepts a DELETE for an rrset that is not there.
func (c *Client) RemoveRecords(ctx context.Context, zone, reverseZone string, recs []tenant.DNSRecord) error {
	return c.records(ctx, zone, reverseZone, recs, "DELETE")
}

func (c *Client) records(ctx context.Context, zone, reverseZone string, recs []tenant.DNSRecord, change string) error {
	if len(recs) == 0 {
		return nil
	}
	var forward, reverse []rrset
	for _, r := range recs {
		fqName := r.Name + "." + fqdn(zone)
		forward = append(forward, rrset{
			Name: fqName, Type: "A", TTL: recordTTL, ChangeType: change,
			Records: records(change, r.Address),
		})
		ptr, err := ptrName(r.Address)
		if err != nil {
			return err
		}
		reverse = append(reverse, rrset{
			Name: ptr, Type: "PTR", TTL: recordTTL, ChangeType: change,
			Records: records(change, fqName),
		})
	}
	if err := c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(fqdn(zone)), map[string]any{"rrsets": forward}, nil); err != nil {
		return fmt.Errorf("zone %s: %w", zone, err)
	}
	if err := c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(fqdn(reverseZone)), map[string]any{"rrsets": reverse}, nil); err != nil {
		return fmt.Errorf("zone %s: %w", reverseZone, err)
	}
	return nil
}

// A DELETE carries no records; a REPLACE carries the one content.
func records(change, content string) []record {
	if change == "DELETE" {
		return []record{}
	}
	return []record{{Content: content}}
}

// ptrName is the reverse name of an IPv4 address: 10.20.129.10 becomes
// 10.129.20.10.in-addr.arpa.
func ptrName(address string) (string, error) {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("%q is not an IPv4 address", address)
	}
	o := strings.Split(ip.To4().String(), ".")
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", o[3], o[2], o[1], o[0]), nil
}
