// deevnet-log-user maintains the log store's vmauth users.
//
// It is invoked two ways, and both render the same file from the same inputs:
//
//   - by sshd, as a forced command, with one logauth.Request on stdin. That is
//     the Deevnet API adding or removing one tenant's users (CHG-0020).
//   - by Ansible, as "--render", after it has written the base file. That is
//     the substrate re-asserting the store's configuration.
//
// Neither owns auth.yml. Ansible owns base.json, this program owns
// users.d/<tenant>.json, and auth.yml is generated from both - so an Ansible
// run cannot drop a tenant's users and a writer run cannot drop the operator's.
//
// Three prohibitions, as for deevnet-broker-account:
//
//   - It never reads SSH_ORIGINAL_COMMAND. What the caller typed is not input;
//     the key is pinned to this program with command=.
//   - It never renders a value it has not validated. Everything it writes into
//     YAML is constrained by logauth's validation to characters that cannot end
//     a scalar early, so the document cannot be broken out of.
//   - It never returns detail to the caller. One Response goes to stdout;
//     anything worth reading goes to stderr, which sshd carries back to the
//     API's log.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// configPath is fixed, not taken from the environment or the command line.
// sshd passes the client no environment, and a fixed path cannot be redirected
// by a caller.
const configPath = "/etc/deevnet/log-user.json"

type config struct {
	Comment string `json:"_comment"`
	// Base is what Ansible owns: the backend URL and the operator and bridge
	// tokens.
	Base string `json:"base"`
	// UsersDir holds one file per tenant, owned by this program.
	UsersDir string `json:"users_dir"`
	// AuthFile is the generated vmauth configuration.
	AuthFile string `json:"auth_file"`
	// ReloadURL is vmauth's internal listener, which is loopback-only, so this
	// program needs no privilege to ask for a reload.
	ReloadURL      string `json:"reload_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// base is the half of the configuration the substrate owns.
type base struct {
	Comment string `json:"_comment"`
	Backend string `json:"backend"`
	// OperatorToken reads every partition, one at a time.
	OperatorToken string `json:"operator_token"`
	// BridgeToken is the MQTT bridge's single token (ADR-0027 §4). Empty until
	// the bridge exists, and then the bridge user is not rendered at all.
	BridgeToken string `json:"bridge_token"`
}

// tenantFile is one tenant's users, as this program stores them.
type tenantFile struct {
	Version     int    `json:"version"`
	Tenant      string `json:"tenant"`
	Index       int    `json:"index"`
	IngestToken string `json:"ingest_token"`
	ReadToken   string `json:"read_token"`
}

func main() {
	render := len(os.Args) > 1 && os.Args[1] == "--render"

	if render {
		// Ansible's path: no request, no response document, an exit status and
		// whatever is on stderr.
		if err := renderOnly(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	resp := run()
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, "writing response:", err)
		os.Exit(1)
	}
	if !resp.OK {
		os.Exit(1)
	}
}

func renderOnly() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()
	if err := regenerate(ctx, cfg); err != nil {
		return err
	}
	return nil
}

// run does the work and always produces a Response. The error text it returns
// to the caller says what is wrong with the request, never what is wrong with
// this host.
func run() logauth.Response {
	resp := logauth.Response{Version: logauth.Version}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading config:", err)
		resp.Message = "the writer is not configured correctly"
		return resp
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()

	req, err := logauth.Decode(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "decoding request:", err)
		resp.Message = "the request could not be read"
		return resp
	}
	if err := req.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "invalid request:", err)
		resp.Message = err.Error()
		return resp
	}

	path := filepath.Join(cfg.UsersDir, req.Tenant+".json")
	existed := fileExists(path)

	switch req.Op {
	case logauth.OpPut:
		f := tenantFile{
			Version:     logauth.Version,
			Tenant:      req.Tenant,
			Index:       req.Index,
			IngestToken: req.IngestToken,
			ReadToken:   req.ReadToken,
		}
		body, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "encoding tenant file:", err)
			resp.Message = "the tenant's users could not be written"
			return resp
		}
		// 0600: this file holds two bearer tokens.
		if err := writeFile(path, append(body, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "writing tenant file:", err)
			resp.Message = "the tenant's users could not be written"
			return resp
		}
	case logauth.OpDelete:
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "removing tenant file:", err)
			resp.Message = "the tenant's users could not be removed"
			return resp
		}
	}

	if err := regenerate(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "regenerating:", err)
		resp.Message = "the store's configuration could not be regenerated"
		return resp
	}

	resp.OK = true
	resp.Existed = existed
	return resp
}

// regenerate renders auth.yml from the base file and every tenant file, then
// asks vmauth to reload. The rendered file is written to a temporary name and
// renamed, so a reader never sees a half-written configuration.
func regenerate(ctx context.Context, cfg config) error {
	b, err := loadBase(cfg.Base)
	if err != nil {
		return err
	}
	tenants, err := loadTenants(cfg.UsersDir)
	if err != nil {
		return err
	}
	doc, err := render(b, tenants)
	if err != nil {
		return err
	}
	if err := writeFile(cfg.AuthFile, doc, 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", cfg.AuthFile, err)
	}
	return reload(ctx, cfg.ReloadURL)
}

// render builds the whole vmauth configuration.
//
// Every url_map entry sets both partition headers, because VictoriaLogs'
// default is the substrate partition (0, 0): an entry that forgot them would
// fail OPEN into substrate logs rather than closed. vmauth replaces a caller's
// header of the same name, so a caller cannot choose its own partition.
//
// A caller selects among the partitions its own user has by sending
// X-Deevnet-Partition: <account>-<project>. That header only chooses between
// entries this file already contains, and each entry then overwrites the
// partition headers and clears the selector.
func render(b base, tenants []tenantFile) ([]byte, error) {
	if b.Backend == "" {
		return nil, errors.New("the base file names no backend")
	}
	if err := validToken("operator_token", b.OperatorToken); err != nil {
		return nil, err
	}

	var w bytes.Buffer
	fmt.Fprintf(&w, "# Generated by deevnet-log-user. Do not edit.\n")
	fmt.Fprintf(&w, "#\n")
	fmt.Fprintf(&w, "# Sources: the base file (Ansible) and %d tenant file(s) (the Deevnet API).\n", len(tenants))
	fmt.Fprintf(&w, "# Editing this file by hand lasts until the next tenant is created.\n\n")
	fmt.Fprintf(&w, "users:\n")

	// The operator: reads any partition, one at a time (ADR-0022, Q1).
	// The substrate partition is the default when no selector is sent.
	operator := []route{{paths: selectPaths, account: 0, project: 0}}
	for _, t := range tenants {
		for _, p := range []int{0, 1, 2} {
			operator = append(operator, route{paths: selectPaths, selector: partition(t.Index, p), account: t.Index, project: p})
		}
	}
	// Ordered so the selector entries are tried before the catch-all.
	writeUser(&w, "operator-read", b.OperatorToken, b.Backend, withSelectorsFirst(operator))

	for _, t := range tenants {
		if err := validTenant(t); err != nil {
			return nil, err
		}
		// Ingest: the tenant's own partition, and nothing else.
		writeUser(&w, "ingest-"+t.Tenant, t.IngestToken, b.Backend, []route{
			{paths: insertPaths, account: t.Index, project: 0},
		})
		// Read: its three partitions, its own first.
		reads := []route{{paths: selectPaths, account: t.Index, project: 0}}
		for _, p := range []int{0, 1, 2} {
			reads = append(reads, route{paths: selectPaths, selector: partition(t.Index, p), account: t.Index, project: p})
		}
		writeUser(&w, "read-"+t.Tenant, t.ReadToken, b.Backend, withSelectorsFirst(reads))
	}

	// The MQTT bridge: one user, one entry per tenant, selected by the tenant
	// header the bridge sets (ADR-0027, open question 1). It writes each
	// tenant's device partition and can reach no other.
	if b.BridgeToken != "" {
		if err := validToken("bridge_token", b.BridgeToken); err != nil {
			return nil, err
		}
		var routes []route
		for _, t := range tenants {
			routes = append(routes, route{
				paths:    insertPaths,
				selector: tenantSelector(t.Tenant),
				account:  t.Index,
				project:  2,
			})
		}
		// With no tenants there is nothing the bridge may write, and a user
		// with no url_map would be a configuration error, so it is omitted.
		if len(routes) > 0 {
			writeUser(&w, "mqtt-bridge", b.BridgeToken, b.Backend, routes)
		}
	}

	return w.Bytes(), nil
}

const (
	selectPaths = `["/select/.*"]`
	insertPaths = `["/insert/.*"]`

	// partitionHeader selects between the partitions a user already has.
	partitionHeader = "X-Deevnet-Partition"
	// tenantHeader is how the bridge says which tenant a message came from.
	tenantHeader = "X-Deevnet-Tenant"
)

type route struct {
	paths    string
	selector string // a full "Name: value" header match, or empty for the catch-all
	account  int
	project  int
}

func partition(account, project int) string {
	return fmt.Sprintf("%s: %d-%d", partitionHeader, account, project)
}

func tenantSelector(name string) string {
	return fmt.Sprintf("%s: %s", tenantHeader, name)
}

// withSelectorsFirst puts every entry carrying a selector before the catch-all,
// because vmauth takes the first entry that matches.
func withSelectorsFirst(in []route) []route {
	var sel, catch []route
	for _, r := range in {
		if r.selector == "" {
			catch = append(catch, r)
		} else {
			sel = append(sel, r)
		}
	}
	return append(sel, catch...)
}

func writeUser(w *bytes.Buffer, name, token, backend string, routes []route) {
	fmt.Fprintf(w, "  - name: %q\n", name)
	fmt.Fprintf(w, "    bearer_token: %q\n", token)
	fmt.Fprintf(w, "    url_map:\n")
	for _, r := range routes {
		fmt.Fprintf(w, "      - src_paths: %s\n", r.paths)
		if r.selector != "" {
			fmt.Fprintf(w, "        src_headers: [%q]\n", r.selector)
		}
		fmt.Fprintf(w, "        url_prefix: %q\n", backend)
		fmt.Fprintf(w, "        headers:\n")
		fmt.Fprintf(w, "          - \"AccountID: %d\"\n", r.account)
		fmt.Fprintf(w, "          - \"ProjectID: %d\"\n", r.project)
		// Clear the selectors on the way to the backend: they are this proxy's
		// business, not the store's.
		fmt.Fprintf(w, "          - %q\n", partitionHeader+":")
		fmt.Fprintf(w, "          - %q\n", tenantHeader+":")
	}
}

func validTenant(t tenantFile) error {
	r := logauth.Request{Version: logauth.Version, Op: logauth.OpPut, Tenant: t.Tenant, Index: t.Index,
		IngestToken: t.IngestToken, ReadToken: t.ReadToken}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("tenant file for %q: %w", t.Tenant, err)
	}
	return nil
}

func validToken(field, tok string) error {
	r := logauth.Request{Version: logauth.Version, Op: logauth.OpPut, Tenant: "x", Index: 1,
		IngestToken: tok, ReadToken: tok + "x"}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func loadConfig() (config, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return config{}, err
	}
	if cfg.Base == "" || cfg.UsersDir == "" || cfg.AuthFile == "" || cfg.ReloadURL == "" {
		return config{}, errors.New("base, users_dir, auth_file and reload_url are all required")
	}
	return cfg, nil
}

func (c config) timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func loadBase(path string) (base, error) {
	f, err := os.Open(path)
	if err != nil {
		return base{}, fmt.Errorf("opening base file: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var b base
	if err := dec.Decode(&b); err != nil {
		return base{}, fmt.Errorf("reading base file: %w", err)
	}
	return b, nil
}

// loadTenants reads every tenant file, in name order so the rendered document
// is stable and a diff means something changed.
func loadTenants(dir string) ([]tenantFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []tenantFile
	for _, n := range names {
		body, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", n, err)
		}
		var t tenantFile
		if err := json.Unmarshal(body, &t); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", n, err)
		}
		out = append(out, t)
	}
	return out, nil
}

// writeFile writes through a temporary file in the same directory and renames,
// so a reader sees either the old file or the new one.
func writeFile(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// reload asks vmauth to re-read its configuration. A write that is not followed
// by a reload is a credential the store does not honour yet, which is exactly
// the ambiguity the API must not be left with.
func reload(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("asking vmauth to reload: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vmauth refused the reload: %s", resp.Status)
	}
	return nil
}
