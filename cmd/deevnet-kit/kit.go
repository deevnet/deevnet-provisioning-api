package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The services the image runs, by unit name.
var units = []string{"mosquitto", "victorialogs", "vmauth", "deevnet-log-bridge", "grafana", "deevnet-kit-dashboards"}

const (
	// The ports are Deevnet's, so an app moved from Deevnet changes a host
	// name and nothing else.
	brokerPort = 8883
	logPort    = 8427
	// Grafana's, as on Deevnet (CHG-0024).
	dashboardPort = 3000

	// The bridge's broker account. The leading underscore keeps it out of
	// the <tenant>-<name> space: no tenant name starts with one.
	bridgeUser = "_log-bridge"

	// Owners on the image. mosquitto comes with its package; the image
	// creates the rest.
	mosquittoUser = "mosquitto"
	storeUser     = "victoria"
	tlsGroup      = "deevnet-kit"

	defaultBootConfig = "/boot/firmware/deevnet-kit.txt"
	defaultTenant     = "pi"
)

// state is what init decides once and every later command reads.
type state struct {
	Version int    `json:"version"`
	Tenant  string `json:"tenant"`
	// Index is the tenant's number, which is in the partition selector an
	// app sends (X-Deevnet-Partition: <index>-2). Set it to the tenant's
	// index on Deevnet and that header does not change either.
	Index int `json:"index"`

	OperatorToken    string `json:"operator_token"`
	IngestToken      string `json:"ingest_token"`
	ReadToken        string `json:"read_token"`
	BridgeStoreToken string `json:"bridge_store_token"`
	BridgePassword   string `json:"bridge_password"`

	// Grafana (ADR-0024, CHG-0024). The admin is the Pi's owner's; the
	// tenant's login is what an app and its Terraform use, as on Deevnet.
	// DashboardOrg is 0 until `deevnet-kit dashboards` has run once.
	GrafanaAdminPassword string `json:"grafana_admin_password"`
	GrafanaSecretKey     string `json:"grafana_secret_key"`
	DashboardPassword    string `json:"dashboard_password"`
	DashboardOrg         int    `json:"dashboard_org"`
}

// kit holds the paths. root is empty on a Pi and a temporary directory in
// tests; nothing else about the program changes between the two.
type kit struct {
	root    string
	noOwner bool // tests: skip chown, the users do not exist
	noExec  bool // tests: do not run systemctl or deevnet-log-user
}

func newKit(root string) *kit { return &kit{root: root} }

func (k *kit) p(path string) string { return filepath.Join(k.root, path) }

func (k *kit) etc() string          { return k.p("/etc/deevnet-kit") }
func (k *kit) stateFile() string    { return filepath.Join(k.etc(), "kit.json") }
func (k *kit) accountsDir() string  { return filepath.Join(k.etc(), "accounts") }
func (k *kit) tlsDir() string       { return filepath.Join(k.etc(), "tls") }
func (k *kit) caFile() string       { return filepath.Join(k.tlsDir(), "ca.pem") }
func (k *kit) bridgeEnv() string    { return filepath.Join(k.etc(), "log-bridge.env") }
func (k *kit) grafanaEnv() string   { return filepath.Join(k.etc(), "grafana.env") }
func (k *kit) logDir() string       { return filepath.Join(k.etc(), "log") }
func (k *kit) mosquittoDir() string { return k.p("/etc/mosquitto/deevnet-kit") }

// --- init -----------------------------------------------------------------------

func (k *kit) cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultBootConfig, "the boot partition's deevnet-kit.txt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(k.stateFile()); err == nil {
		// First boot runs once. Running it again would mint new tokens and a
		// new CA, and strand every app and device already configured.
		fmt.Println("already initialised; nothing to do")
		return nil
	}

	name, index, err := readBootConfig(*cfgPath)
	if err != nil {
		return err
	}
	st := state{Version: 1, Tenant: name, Index: index}
	for _, t := range []*string{&st.OperatorToken, &st.IngestToken, &st.ReadToken, &st.BridgeStoreToken, &st.BridgePassword,
		&st.GrafanaAdminPassword, &st.GrafanaSecretKey, &st.DashboardPassword} {
		if *t, err = randomHex(32); err != nil {
			return err
		}
	}
	if err := validState(st); err != nil {
		return err
	}

	for _, d := range []string{k.etc(), k.accountsDir(), k.tlsDir(), k.logDir(), k.mosquittoDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := k.issueCA(); err != nil {
		return err
	}
	if err := k.issueServerCert(); err != nil {
		return err
	}
	// The state is written LAST of the secrets: its presence is what says
	// init finished, so a half-done init is retried rather than skipped.
	if err := k.renderAllFrom(st, false); err != nil {
		return err
	}
	if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
		return err
	}
	fmt.Printf("initialised tenant %q (index %d); run: sudo deevnet-kit export ~/deevnet-kit\n", st.Tenant, st.Index)
	return nil
}

// readBootConfig reads key=value lines. A missing file is not an error: the
// card still has to come up, as tenant "pi".
func readBootConfig(path string) (string, int, error) {
	name, index := defaultTenant, 1
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return name, index, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r")) // edited on Windows
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return "", 0, fmt.Errorf("%s: %q is not key=value", path, line)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "tenant":
			if val != "" {
				name = val
			}
		case "index":
			if val != "" {
				if index, err = strconv.Atoi(val); err != nil {
					return "", 0, fmt.Errorf("%s: index %q is not a number", path, val)
				}
			}
		default:
			return "", 0, fmt.Errorf("%s: unknown key %q", path, key)
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	if !tenant.ValidName(name) {
		return "", 0, fmt.Errorf("%s: tenant %q is not a tenant name (1-8 lowercase alphanumerics, starting with a letter)", path, name)
	}
	return name, index, nil
}

// validState applies the log store's own contract to what init chose, so a
// state the renderer would refuse is refused here, before anything is written.
func validState(st state) error {
	r := logauth.Request{Version: logauth.Version, Op: logauth.OpPut, Tenant: st.Tenant, Index: st.Index,
		IngestToken: st.IngestToken, ReadToken: st.ReadToken}
	return r.Validate()
}

func (k *kit) loadState() (state, error) {
	var st state
	b, err := os.ReadFile(k.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return st, fmt.Errorf("not initialised: run deevnet-kit init (first boot does this)")
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("%s: %w", k.stateFile(), err)
	}
	return st, validState(st)
}

// --- rendering --------------------------------------------------------------------

func (k *kit) renderAll(reload bool) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	return k.renderAllFrom(st, reload)
}

func (k *kit) renderAllFrom(st state, reload bool) error {
	if err := k.renderBroker(st, reload); err != nil {
		return err
	}
	if err := k.renderLogStore(st, reload); err != nil {
		return err
	}
	if err := k.writeGrafanaEnv(st); err != nil {
		return err
	}
	return k.writeBridgeEnv(st)
}

// renderLogStore writes deevnet-log-user's inputs and has it render vmauth's
// configuration, so the users on this Pi are the users Deevnet would write
// for the same tenant.
func (k *kit) renderLogStore(st state, reload bool) error {
	usersDir := filepath.Join(k.logDir(), "users.d")
	authDir := filepath.Join(k.logDir(), "auth")
	for _, d := range []string{usersDir, authDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	base := map[string]string{
		"_comment":       "deevnet-kit - the half of the store's users the image owns",
		"backend":        "http://127.0.0.1:9428/",
		"operator_token": st.OperatorToken,
		"bridge_token":   st.BridgeStoreToken,
	}
	if err := writeJSON(filepath.Join(k.logDir(), "base.json"), base, 0o600); err != nil {
		return err
	}
	users := map[string]any{
		"version": 1, "tenant": st.Tenant, "index": st.Index,
		"ingest_token": st.IngestToken, "read_token": st.ReadToken,
	}
	if err := writeJSON(filepath.Join(usersDir, st.Tenant+".json"), users, 0o600); err != nil {
		return err
	}
	// vmauth runs as the store's user and reads what the renderer writes, so
	// the renderer runs as that user too.
	for _, p := range []string{k.logDir(), usersDir, authDir, filepath.Join(k.logDir(), "base.json"), filepath.Join(usersDir, st.Tenant+".json")} {
		if err := k.chown(p, storeUser, storeUser); err != nil {
			return err
		}
	}
	if k.noExec {
		return nil
	}
	argv := []string{"runuser", "-u", storeUser, "--", "/usr/local/bin/deevnet-log-user", "--render"}
	if !reload {
		argv = append(argv, "--no-reload")
	}
	return runCmd(argv...)
}

func (k *kit) writeBridgeEnv(st state) error {
	env := fmt.Sprintf(`# deevnet-kit - generated; the log bridge's environment
DEEVNET_BRIDGE_BROKER_URL=ssl://localhost:%d
DEEVNET_BRIDGE_BROKER_USERNAME=%s
DEEVNET_BRIDGE_BROKER_PASSWORD=%s
DEEVNET_BRIDGE_BROKER_CA_FILE=%s
DEEVNET_BRIDGE_STORE_URL=https://localhost:%d
DEEVNET_BRIDGE_STORE_TOKEN=%s
DEEVNET_BRIDGE_STORE_CA_FILE=%s
`, brokerPort, bridgeUser, st.BridgePassword, k.caFileOnHost(), logPort, st.BridgeStoreToken, k.caFileOnHost())
	return writeFile(k.bridgeEnv(), []byte(env), 0o600)
}

// caFileOnHost is the CA's path as the services see it, which in tests is not
// where the test wrote it.
func (k *kit) caFileOnHost() string { return "/etc/deevnet-kit/tls/ca.pem" }

// --- env, export, status ----------------------------------------------------------------

// host is the name the app dials. mDNS gives every Pi <hostname>.local with no
// DNS to run.
func host() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "raspberrypi"
	}
	return h + ".local"
}

func (k *kit) cmdEnv(w io.Writer) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, kitEnv(st, host()))
	return err
}

// kitEnv is the app's whole view of this Pi. The names are the tenant guide's;
// the same file built from Terraform outputs points the same app at Deevnet.
func kitEnv(st state, h string) string {
	return fmt.Sprintf(`# deevnet-kit - tenant %s on %s
# The same names, filled from terraform outputs, point this app at Deevnet.
DEEVNET_TENANT=%s
MQTT_HOST=%s
MQTT_PORT=%d
MQTT_CA_FILE=site-ca.pem
LOG_ENDPOINT=https://%s:%d
LOG_INGEST_TOKEN=%s
LOG_READ_TOKEN=%s
LOG_SELECT_HEADER=X-Deevnet-Partition
LOG_DEVICE_PARTITION=%d-2
`, st.Tenant, h, st.Tenant, h, brokerPort, h, logPort, st.IngestToken, st.ReadToken, st.Index) + dashboardEnv(st, h)
}

func (k *kit) cmdExport(dir string) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, err := os.ReadFile(k.caFile())
	if err != nil {
		return err
	}
	envPath, caPath := filepath.Join(dir, "kit.env"), filepath.Join(dir, "site-ca.pem")
	if err := writeFile(envPath, []byte(kitEnv(st, host())), 0o600); err != nil {
		return err
	}
	if err := writeFile(caPath, ca, 0o644); err != nil {
		return err
	}
	// Run under sudo, the files would otherwise belong to root in the
	// owner's own home.
	if uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); uid != "" && gid != "" {
		u, _ := strconv.Atoi(uid)
		g, _ := strconv.Atoi(gid)
		for _, p := range []string{dir, envPath, caPath} {
			if err := os.Chown(p, u, g); err != nil {
				return err
			}
		}
	}
	fmt.Printf("wrote %s and %s\n", envPath, caPath)
	return nil
}

func (k *kit) cmdStatus() error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	h := host()
	fmt.Printf("tenant   %s (index %d)\n", st.Tenant, st.Index)
	fmt.Printf("broker   mqtts://%s:%d\n", h, brokerPort)
	fmt.Printf("logs     https://%s:%d  (device logs: X-Deevnet-Partition: %d-2)\n", h, logPort, st.Index)
	if st.DashboardOrg > 0 {
		fmt.Printf("grafana  https://%s:%d  (login %s; organisation %d)\n", h, dashboardPort, st.Tenant, st.DashboardOrg)
	} else {
		fmt.Printf("grafana  https://%s:%d  (not set up yet: systemctl status deevnet-kit-dashboards)\n", h, dashboardPort)
	}
	fmt.Println()
	bad := 0
	for _, u := range units {
		out, _ := exec.Command("systemctl", "is-active", u).Output()
		s := strings.TrimSpace(string(out))
		if s != "active" {
			bad++
		}
		fmt.Printf("  %-20s %s\n", u, s)
	}
	accts, err := k.loadAccounts()
	if err != nil {
		return err
	}
	fmt.Printf("\n%d broker account(s); deevnet-kit account list\n", len(accts))
	missing, err := k.uncoveredAddrs()
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		// Not a failure of the services, but a device dialling this address
		// will refuse the certificate - and say only "TLS error".
		fmt.Printf("\nthe certificate does not name %v; a device dialling it will fail - run: sudo deevnet-kit regen-certs\n", missing)
	}
	if bad > 0 {
		return fmt.Errorf("%d service(s) not active", bad)
	}
	return nil
}

// --- helpers --------------------------------------------------------------------------

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), mode)
}

// writeFile writes through a temporary file and renames, so a service that
// reloads mid-write reads the old file or the new one, never half of one.
func writeFile(path string, body []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
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

// chown hands a file to a service's user. A user the image should have
// created and did not is an error: the service would fail to read the file,
// later and less clearly.
func (k *kit) chown(path, owner, group string) error {
	if k.noOwner {
		return nil
	}
	uid, gid := 0, 0
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return fmt.Errorf("user %s: %w", owner, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("group %s: %w", group, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return os.Chown(path, uid, gid)
}

func runCmd(argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv[:min(len(argv), 5)], " "), err)
	}
	return nil
}
