// Package grafana ensures a tenant's organisation, login and data sources in
// the dashboard server (ADR-0024, CHG-0024) through Grafana's HTTP API.
//
// One organisation per tenant is the boundary. Grafana OSS has no data-source
// permissions inside an organisation, so a tenant that shared one could query
// anything the organisation's data sources can reach. The tenant's login is an
// Editor in its own organisation and a member of nothing else: an Editor can
// build dashboards and use the data sources, but cannot create a data source,
// and a data source is a URL Grafana's server requests on the caller's behalf
// (ADR-0024 §3).
//
// The data sources are the contract, and their UIDs are fixed: the same three
// in every tenant's organisation, on every site, and on the take-home Pi. That
// is what lets a dashboard's JSON move between them unchanged. Each one carries
// the tenant's log read token, so a query runs under the log store's own
// boundary rather than one Grafana would have to enforce.
//
// The Pi's deevnet-kit calls this package too, against its own Grafana, so the
// rules here are the Pi's as well.
//
// Behaviour relied on here was checked against Grafana 13.2.2:
//   - GET /api/orgs/name/<n> and /api/users/lookup answer 404 when absent
//   - a server admin creating an organisation is made an Admin of it; the
//     membership is still ensured, because nothing else here can act in it
//   - a user created with "OrgId" joins that organisation only, as Viewer -
//     but ONLY while users.auto_assign_org is on (the default). With it off,
//     OrgId is ignored and Grafana makes every new user a personal
//     organisation named for its login, which here is the tenant's own name
//   - DELETE /api/orgs/<id> answers 500 on every 12.x and 13.x release with
//     unified storage (grafana/grafana#127386; the fix, #127404, is unmerged).
//     Remove works around it - see retireOrg
//   - secureJsonData cannot be read back, so data sources are always written
package grafana

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// PluginID is the VictoriaLogs data source plugin (Apache 2.0). It must be
// installed on the server; it is not in Grafana's image.
const PluginID = "victoriametrics-logs-datasource"

// PartitionHeader selects which of the tenant's partitions a read token reads
// (ADR-0027 §2). vmauth matches it and sets the store's own headers itself.
const PartitionHeader = "X-Deevnet-Partition"

// DataSource is one of the data sources every tenant organisation has.
type DataSource struct {
	UID  string
	Name string
	// Project is the partition's second number: (index, Project).
	Project int
	// Default is the organisation's default data source.
	Default bool
}

// DataSources is the contract (ADR-0024 §2 as amended by CHG-0024). Change a
// UID and every tenant's dashboards stop finding their data.
var DataSources = []DataSource{
	{UID: "deevnet-logs-workloads", Name: "Workload logs", Project: 0},
	{UID: "deevnet-logs-platform", Name: "Platform logs", Project: 1},
	{UID: "deevnet-logs-devices", Name: "Device logs", Project: 2, Default: true},
}

// TenantRole is what a tenant's login is in its own organisation. Never Admin:
// an Admin can create data sources.
const TenantRole = "Editor"

// Config is what a client needs.
type Config struct {
	// URL is the server's root, for example https://obs.example:3000.
	URL string
	// AdminUser and AdminPassword are the server admin's. Creating an
	// organisation is a server-admin act; no organisation-scoped token can.
	AdminUser     string
	AdminPassword string
	// CAFile verifies the server. Its content is also what the data sources
	// verify the log store with, since both carry certificates from the site
	// CA; LogCA overrides that when they differ.
	CAFile string
	LogCA  string
	// LogEndpoint is the log store as Grafana's server reaches it.
	LogEndpoint string
	Timeout     time.Duration
}

// Client is a tenant.Dashboards.
type Client struct {
	cfg   Config
	base  string
	logCA string
	http  *http.Client
}

// New validates the configuration and reads the CA now, so a bad path is a
// startup failure rather than a failed apply.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.URL == "":
		return nil, errors.New("dashboard server URL is required")
	case cfg.AdminUser == "" || cfg.AdminPassword == "":
		return nil, errors.New("dashboard server admin credentials are required")
	case cfg.LogEndpoint == "":
		return nil, errors.New("the log endpoint is required: the data sources point at it")
	case cfg.CAFile == "":
		return nil, errors.New("a CA file is required; this client does not skip verification")
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("dashboard CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("dashboard CA %s holds no certificate", cfg.CAFile)
	}
	logCA := cfg.LogCA
	if logCA == "" {
		logCA = string(pem)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Client{
		cfg:   cfg,
		base:  strings.TrimRight(cfg.URL, "/"),
		logCA: logCA,
		http: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

var errNotFound = errors.New("not found")

// statusError is a refusal from the server. Its message is Grafana's own,
// which names what was wrong and never echoes a password.
type statusError struct {
	method, path string
	code         int
	msg          string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s %s: %d %s", e.method, e.path, e.code, e.msg)
}

func isStatus(err error, code int) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == code
}

// Ensure brings one tenant's organisation, login and data sources into line
// and returns the organisation's id.
func (c *Client) Ensure(ctx context.Context, t tenant.DashTenant) (int, error) {
	if err := c.refuseAdminName(t.Name); err != nil {
		return 0, err
	}
	org, err := c.ensureOrg(ctx, t.Name)
	if err != nil {
		return 0, fmt.Errorf("organisation: %w", err)
	}
	if err := c.ensureUser(ctx, t, org); err != nil {
		return 0, fmt.Errorf("login: %w", err)
	}
	for _, ds := range DataSources {
		if err := c.ensureDataSource(ctx, org, t, ds); err != nil {
			return 0, fmt.Errorf("data source %s: %w", ds.UID, err)
		}
	}
	return org, nil
}

// Remove deletes the tenant's login and organisation. Either being absent
// already is success: a delete that failed half way is finished by calling
// it again.
func (c *Client) Remove(ctx context.Context, name string) error {
	if err := c.refuseAdminName(name); err != nil {
		return err
	}
	u, err := c.lookupUser(ctx, name)
	switch {
	case errors.Is(err, errNotFound):
	case err != nil:
		return fmt.Errorf("login: %w", err)
	case u.IsGrafanaAdmin:
		return fmt.Errorf("login %q is a server admin; refusing to delete it as a tenant's", name)
	default:
		if err := c.do(ctx, http.MethodDelete, "/api/admin/users/"+strconv.Itoa(u.ID), 0, nil, nil); err != nil && !isStatus(err, 404) {
			return fmt.Errorf("login: %w", err)
		}
	}
	org, err := c.lookupOrg(ctx, name)
	switch {
	case errors.Is(err, errNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("organisation: %w", err)
	case org == 1:
		return errors.New("refusing to delete organisation 1, the operator's")
	}
	// The data sources first: they hold the read token, and if the
	// organisation itself cannot be deleted they must not outlive the tenant.
	for _, ds := range DataSources {
		err := c.do(ctx, http.MethodDelete, "/api/datasources/uid/"+url.PathEscape(ds.UID), org, nil, nil)
		if err != nil && !isStatus(err, 404) {
			return fmt.Errorf("data source %s: %w", ds.UID, err)
		}
	}
	err = c.do(ctx, http.MethodDelete, "/api/orgs/"+strconv.Itoa(org), 0, nil, nil)
	switch {
	case err == nil, isStatus(err, 404):
		return nil
	case isStatus(err, 500):
		return c.retireOrg(ctx, name, org)
	default:
		return fmt.Errorf("organisation: %w", err)
	}
}

// retireOrg renames an organisation the server will not delete, so the name
// is free for a tenant created again under it. By this point it holds no
// data source and no tenant login, only whatever dashboards the tenant left,
// which read nothing. When the upstream fix ships, the delete above succeeds
// and this is never reached.
func (c *Client) retireOrg(ctx context.Context, name string, org int) error {
	retired := fmt.Sprintf("deleted-%s-%d", name, org)
	if err := c.do(ctx, http.MethodPut, "/api/orgs/"+strconv.Itoa(org), 0, map[string]string{"name": retired}, nil); err != nil {
		return fmt.Errorf("organisation could not be deleted, nor renamed to %s: %w", retired, err)
	}
	return nil
}

// A tenant name is 1-8 lowercase alphanumerics, which "admin" is. A tenant by
// the admin's name would have this package reset the admin's password to the
// tenant's, so it is refused outright rather than left to the lookups below.
func (c *Client) refuseAdminName(name string) error {
	if name == "" || strings.EqualFold(name, c.cfg.AdminUser) {
		return fmt.Errorf("tenant name %q cannot have a dashboard login: it is the server admin's", name)
	}
	return nil
}

// --- organisation ------------------------------------------------------------

func (c *Client) lookupOrg(ctx context.Context, name string) (int, error) {
	var out struct {
		ID int `json:"id"`
	}
	err := c.do(ctx, http.MethodGet, "/api/orgs/name/"+url.PathEscape(name), 0, nil, &out)
	if isStatus(err, 404) {
		return 0, errNotFound
	}
	return out.ID, err
}

func (c *Client) ensureOrg(ctx context.Context, name string) (int, error) {
	org, err := c.lookupOrg(ctx, name)
	if errors.Is(err, errNotFound) {
		var out struct {
			OrgID int `json:"orgId"`
		}
		if err := c.do(ctx, http.MethodPost, "/api/orgs", 0, map[string]string{"name": name}, &out); err != nil {
			return 0, err
		}
		org = out.OrgID
	} else if err != nil {
		return 0, err
	}
	if org <= 1 {
		return 0, fmt.Errorf("the server gave organisation %d, which is the operator's", org)
	}
	// The admin must be a member to write the organisation's data sources.
	// 409 is "already a member", which is the goal.
	err = c.do(ctx, http.MethodPost, fmt.Sprintf("/api/orgs/%d/users", org), 0,
		map[string]string{"loginOrEmail": c.cfg.AdminUser, "role": "Admin"}, nil)
	if err != nil && !isStatus(err, 409) {
		return 0, fmt.Errorf("adding the server admin: %w", err)
	}
	return org, nil
}

// --- login ---------------------------------------------------------------------

type user struct {
	ID             int    `json:"id"`
	Login          string `json:"login"`
	OrgID          int    `json:"orgId"`
	IsGrafanaAdmin bool   `json:"isGrafanaAdmin"`
}

func (c *Client) lookupUser(ctx context.Context, login string) (user, error) {
	var u user
	err := c.do(ctx, http.MethodGet, "/api/users/lookup?loginOrEmail="+url.QueryEscape(login), 0, nil, &u)
	if isStatus(err, 404) {
		return user{}, errNotFound
	}
	return u, err
}

func (c *Client) ensureUser(ctx context.Context, t tenant.DashTenant, org int) error {
	u, err := c.lookupUser(ctx, t.Name)
	switch {
	case errors.Is(err, errNotFound):
		var out struct {
			ID int `json:"id"`
		}
		body := map[string]any{"name": t.Name, "login": t.Name, "password": t.Password, "OrgId": org}
		if err := c.do(ctx, http.MethodPost, "/api/admin/users", 0, body, &out); err != nil {
			return err
		}
		if u, err = c.lookupUser(ctx, t.Name); err != nil {
			return err
		}
	case err != nil:
		return err
	case u.IsGrafanaAdmin:
		return fmt.Errorf("login %q is a server admin; refusing to manage it as a tenant's", t.Name)
	default:
		if err := c.ensurePassword(ctx, u, t.Password); err != nil {
			return err
		}
	}
	if err := c.ensureMembership(ctx, u, t.Name, org); err != nil {
		return err
	}
	if u.OrgID != org {
		if err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/users/%d/using/%d", u.ID, org), 0, nil, nil); err != nil {
			return fmt.Errorf("switching the login to its organisation: %w", err)
		}
	}
	return nil
}

// The password is checked by using it, and set only when that fails. Setting
// it on every reconcile would be simpler and would sign the tenant out of
// every session each time.
func (c *Client) ensurePassword(ctx context.Context, u user, password string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/user", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(u.Login, password)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return c.do(ctx, http.MethodPut, fmt.Sprintf("/api/admin/users/%d/password", u.ID), 0,
			map[string]string{"password": password}, nil)
	default:
		return fmt.Errorf("checking the login's password: %d", resp.StatusCode)
	}
}

// Editor in its own organisation, and a member of no other. Added before
// anything is removed, so the login always belongs somewhere.
func (c *Client) ensureMembership(ctx context.Context, u user, login string, org int) error {
	var orgs []struct {
		OrgID int    `json:"orgId"`
		Role  string `json:"role"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/users/%d/orgs", u.ID), 0, nil, &orgs); err != nil {
		return err
	}
	member := false
	for _, o := range orgs {
		if o.OrgID != org {
			continue
		}
		member = true
		if o.Role != TenantRole {
			if err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/orgs/%d/users/%d", org, u.ID), 0,
				map[string]string{"role": TenantRole}, nil); err != nil {
				return fmt.Errorf("setting the login's role: %w", err)
			}
		}
	}
	if !member {
		if err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/orgs/%d/users", org), 0,
			map[string]string{"loginOrEmail": login, "role": TenantRole}, nil); err != nil && !isStatus(err, 409) {
			return fmt.Errorf("adding the login to its organisation: %w", err)
		}
	}
	for _, o := range orgs {
		if o.OrgID == org {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/orgs/%d/users/%d", o.OrgID, u.ID), 0, nil, nil); err != nil && !isStatus(err, 404) {
			return fmt.Errorf("removing the login from organisation %d: %w", o.OrgID, err)
		}
	}
	return nil
}

// --- data sources ----------------------------------------------------------------

// DataSourceBody is what is written for one data source. Exported for the
// tests and for anything that needs to see the contract as the server does.
func DataSourceBody(ds DataSource, index int, readToken, logEndpoint, logCA string) map[string]any {
	return map[string]any{
		"uid":       ds.UID,
		"name":      ds.Name,
		"type":      PluginID,
		"access":    "proxy",
		"url":       logEndpoint,
		"isDefault": ds.Default,
		"jsonData": map[string]any{
			"httpHeaderName1":   "Authorization",
			"httpHeaderName2":   PartitionHeader,
			"tlsAuthWithCACert": true,
		},
		"secureJsonData": map[string]string{
			"httpHeaderValue1": "Bearer " + readToken,
			"httpHeaderValue2": fmt.Sprintf("%d-%d", index, ds.Project),
			"tlsCACert":        logCA,
		},
	}
}

// Always written. The token lives in secureJsonData, which the server never
// returns, so there is nothing to compare a rotated token against; a write is
// the only way to know the data source carries the current one.
func (c *Client) ensureDataSource(ctx context.Context, org int, t tenant.DashTenant, ds DataSource) error {
	body := DataSourceBody(ds, t.Index, t.ReadToken, c.cfg.LogEndpoint, c.logCA)
	path := "/api/datasources/uid/" + url.PathEscape(ds.UID)
	err := c.do(ctx, http.MethodGet, path, org, nil, nil)
	switch {
	case isStatus(err, 404):
		return c.do(ctx, http.MethodPost, "/api/datasources", org, body, nil)
	case err != nil:
		return err
	}
	return c.do(ctx, http.MethodPut, path, org, body, nil)
}

// --- dashboards ------------------------------------------------------------------

// EnsureDashboard creates a dashboard in an organisation when none has its
// UID, and otherwise leaves it alone. It never overwrites: once created, the
// dashboard is the tenant's to change or delete, and a later run must not undo
// that. The take-home Pi uses it for the starter dashboard it opens with.
func (c *Client) EnsureDashboard(ctx context.Context, org int, dashboard map[string]any) error {
	uid, _ := dashboard["uid"].(string)
	if uid == "" {
		return errors.New("a dashboard needs a uid to be ensured")
	}
	err := c.do(ctx, http.MethodGet, "/api/dashboards/uid/"+url.PathEscape(uid), org, nil, nil)
	switch {
	case err == nil:
		return nil
	case !isStatus(err, 404):
		return err
	}
	return c.do(ctx, http.MethodPost, "/api/dashboards/db", org,
		map[string]any{"dashboard": dashboard, "overwrite": false}, nil)
}

// --- transport -------------------------------------------------------------------

// do makes one call as the server admin. A non-zero org selects the
// organisation the call acts in.
func (c *Client) do(ctx context.Context, method, path string, org int, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.AdminUser, c.cfg.AdminPassword)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if org > 0 {
		req.Header.Set("X-Grafana-Org-Id", strconv.Itoa(org))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// The query string is left out of errors: it can hold a login name, which
	// is harmless, but nothing here needs it and the habit is the point.
	shown, _, _ := strings.Cut(path, "?")
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		return &statusError{method: method, path: shown, code: resp.StatusCode, msg: e.Message}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decoding: %w", method, shown, err)
		}
	}
	return nil
}
