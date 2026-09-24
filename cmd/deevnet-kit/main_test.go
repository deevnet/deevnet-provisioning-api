package main

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKit(t *testing.T) *kit {
	t.Helper()
	return &kit{root: t.TempDir(), noOwner: true, noExec: true}
}

func bootConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deevnet-kit.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func initKit(t *testing.T, cfg string) (*kit, state) {
	t.Helper()
	k := testKit(t)
	if err := k.cmdInit([]string{"--config", bootConfig(t, cfg)}); err != nil {
		t.Fatalf("init: %v", err)
	}
	st, err := k.loadState()
	if err != nil {
		t.Fatal(err)
	}
	return k, st
}

func TestBootConfig(t *testing.T) {
	cases := []struct {
		body    string
		tenant  string
		index   int
		wantErr bool
	}{
		{"", "pi", 1, false},
		{"# comment\ntenant=tdemo\r\nindex=2\n", "tdemo", 2, false},
		{"tenant=\nindex=\n", "pi", 1, false},
		{"tenant=Bad\n", "", 0, true},
		{"tenant=waytoolongname\n", "", 0, true},
		{"index=two\n", "", 0, true},
		{"colour=blue\n", "", 0, true},
		{"just words\n", "", 0, true},
	}
	for _, c := range cases {
		name, index, err := readBootConfig(bootConfig(t, c.body))
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: accepted, want an error", c.body)
			}
			continue
		}
		if err != nil || name != c.tenant || index != c.index {
			t.Errorf("%q: got %q %d %v, want %q %d", c.body, name, index, err, c.tenant, c.index)
		}
	}
	if name, index, err := readBootConfig(filepath.Join(t.TempDir(), "absent")); err != nil || name != "pi" || index != 1 {
		t.Errorf("a missing file should default to pi/1, got %q %d %v", name, index, err)
	}
}

func TestInitRefusesAnIndexTheStoreWould(t *testing.T) {
	k := testKit(t)
	if err := k.cmdInit([]string{"--config", bootConfig(t, "index=0\n")}); err == nil {
		t.Fatal("index 0 is the substrate partition and must be refused")
	}
	if _, err := os.Stat(k.stateFile()); err == nil {
		t.Fatal("a refused init left a state file behind")
	}
}

func TestInitRunsOnce(t *testing.T) {
	k, st := initKit(t, "tenant=tdemo\nindex=1\n")
	before, _ := os.ReadFile(k.caFile())
	if err := k.cmdInit([]string{"--config", bootConfig(t, "tenant=other\n")}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(k.caFile())
	st2, _ := k.loadState()
	if string(before) != string(after) || st2 != st {
		t.Fatal("a second init changed the CA or the state; it must be a no-op")
	}
}

func TestInitWritesEverythingTheServicesRead(t *testing.T) {
	k, st := initKit(t, "tenant=tdemo\nindex=3\n")
	for _, p := range []string{
		k.caFile(), k.caKeyFile(), k.serverFile(), k.serverKeyFile(), k.bridgeEnv(),
		filepath.Join(k.mosquittoDir(), "passwd"), filepath.Join(k.mosquittoDir(), "acl"),
		filepath.Join(k.logDir(), "base.json"), filepath.Join(k.logDir(), "users.d", "tdemo.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s", p)
		}
	}
	for _, p := range []string{k.stateFile(), k.caKeyFile(), k.bridgeEnv()} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", p, fi.Mode().Perm())
		}
	}
	if st.IngestToken == st.ReadToken || len(st.IngestToken) != 64 {
		t.Errorf("tokens are not distinct 64-hex values")
	}
	env := kitEnv(st, "kit1.local")
	for _, want := range []string{"DEEVNET_TENANT=tdemo", "MQTT_HOST=kit1.local", "MQTT_PORT=8883",
		"LOG_ENDPOINT=https://kit1.local:8427", "LOG_DEVICE_PARTITION=3-2", "LOG_INGEST_TOKEN=" + st.IngestToken} {
		if !strings.Contains(env, want) {
			t.Errorf("kit.env lacks %q", want)
		}
	}
}

func TestServerCertVerifiesForEveryNameTheClientsDial(t *testing.T) {
	k, _ := initKit(t, "")
	caPEM, _ := os.ReadFile(k.caFile())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	b, _ := os.ReadFile(k.serverFile())
	blk, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := os.Hostname()
	for _, name := range []string{h + ".local", h, "localhost", "127.0.0.1"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A device dials the address, because it cannot resolve .local.
	for _, ip := range localAddrs() {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: ip.String(), Roots: pool}); err != nil {
			t.Errorf("%s: %v", ip, err)
		}
	}
	if missing, err := k.uncoveredAddrs(); err != nil || len(missing) > 0 {
		t.Errorf("a fresh certificate leaves %v uncovered (%v)", missing, err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "mqtt.mobile.deevnet.net", Roots: pool}); err == nil {
		t.Error("the certificate verified for a Deevnet name")
	}
}

// The account rules are the API's; these cases are ADR-0027 §3's.
func TestAccountRules(t *testing.T) {
	st := state{Tenant: "tdemo", Index: 1}
	ok := []struct {
		device   string
		pub, sub []string
	}{
		{"", []string{"sensors/+/telemetry"}, []string{"sensors/+/command"}},
		{"dev1", []string{"log/dev1", "sensors/dev1/telemetry"}, nil},
		{"", nil, []string{"log/#"}},
		{"", nil, []string{"#"}},
	}
	for _, c := range ok {
		a, err := newAccount(st, "acct", c.device, c.pub, c.sub)
		if err != nil {
			t.Errorf("%+v refused: %v", c, err)
			continue
		}
		for _, p := range append(a.Publish, a.Subscribe...) {
			if !strings.HasPrefix(p, "tdemo/") {
				t.Errorf("%q was not prefixed", p)
			}
		}
	}
	refused := []struct {
		name, device string
		pub, sub     []string
	}{
		{"acct", "dev1", []string{"log/dev2"}, nil},           // another device's log
		{"acct", "dev1", []string{"log/+"}, nil},              // a wildcard into log
		{"acct", "dev1", nil, []string{"#"}},                  // a device reading the log space
		{"acct", "", []string{"log/dev1"}, nil},               // a workload writing device logs
		{"acct", "", nil, nil},                                // no grant at all
		{"acct", "", []string{"/abs"}, nil},                   // leading slash
		{"acct", "", []string{"$SYS/#"}, nil},                 // reserved
		{"acct", "", []string{"a/#/b"}, nil},                  // # before the end
		{"acct", "", []string{"a/b+"}, nil},                   // partial +
		{"acct", "", []string{"a\ntopic write other/#"}, nil}, // an injected ACL line
		{"Bad", "", []string{"a"}, nil},                       // name
		{"acct", "Dev", []string{"a"}, nil},                   // device name
	}
	for _, c := range refused {
		if _, err := newAccount(st, c.name, c.device, c.pub, c.sub); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestAccountsRenderToMosquitto(t *testing.T) {
	k, _ := initKit(t, "tenant=tdemo\n")
	if err := k.accountAdd([]string{"sensor", "--device", "dev1", "--publish", "log/dev1",
		"--publish", "sensors/dev1/telemetry", "--password", "kept-from-deevnet"}); err != nil {
		t.Fatal(err)
	}
	if err := k.accountAdd([]string{"app", "--subscribe", "sensors/+/telemetry", "--subscribe", "log/#"}); err != nil {
		t.Fatal(err)
	}
	if err := k.accountAdd([]string{"app", "--subscribe", "x"}); err == nil {
		t.Error("a second account with the same name was accepted")
	}
	acl, _ := os.ReadFile(filepath.Join(k.mosquittoDir(), "acl"))
	want := `user _log-bridge
topic read +/log/#

user tdemo-app
topic read tdemo/sensors/+/telemetry
topic read tdemo/log/#

user tdemo-sensor
topic write tdemo/log/dev1
topic write tdemo/sensors/dev1/telemetry
`
	if !strings.HasSuffix(string(acl), want) {
		t.Errorf("acl:\n%s\nwant it to end:\n%s", acl, want)
	}
	passwd, _ := os.ReadFile(filepath.Join(k.mosquittoDir(), "passwd"))
	var sensorHash string
	for _, line := range strings.Split(strings.TrimSpace(string(passwd)), "\n") {
		u, h, _ := strings.Cut(line, ":")
		if u == "tdemo-sensor" {
			sensorHash = h
		}
	}
	if !checkHash(t, sensorHash, "kept-from-deevnet") {
		t.Error("the supplied password does not verify against the stored hash")
	}

	if err := k.accountRemove("sensor"); err != nil {
		t.Fatal(err)
	}
	acl, _ = os.ReadFile(filepath.Join(k.mosquittoDir(), "acl"))
	passwd, _ = os.ReadFile(filepath.Join(k.mosquittoDir(), "passwd"))
	if strings.Contains(string(acl), "tdemo-sensor") || strings.Contains(string(passwd), "tdemo-sensor") {
		t.Error("a removed account is still in the broker's files")
	}
}

// checkHash verifies a $7$ hash the way Mosquitto does.
func checkHash(t *testing.T, hash, password string) bool {
	t.Helper()
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[1] != "7" || parts[2] != "101" {
		t.Fatalf("%q is not a $7$101$ hash", hash)
	}
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) != 12 {
		t.Fatalf("salt: %v (%d bytes)", err, len(salt))
	}
	want, _ := base64.StdEncoding.DecodeString(parts[4])
	got, _ := pbkdf2.Key(sha512.New, password, salt, 101, sha512.Size)
	return string(got) == string(want)
}

// init mints Grafana's secrets and writes its environment file, and kit.env
// carries the Grafana lines only once the organisation exists.
func TestInitWritesGrafanaSecretsAndKitEnvWaitsForTheOrg(t *testing.T) {
	k, st := initKit(t, "tenant=bench1\nindex=4\n")
	for name, v := range map[string]string{"admin": st.GrafanaAdminPassword, "secret key": st.GrafanaSecretKey, "login": st.DashboardPassword} {
		if len(v) != 64 {
			t.Errorf("grafana %s = %q, want 64 hex characters", name, v)
		}
	}
	b, err := os.ReadFile(k.grafanaEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "GF_SECURITY_ADMIN_PASSWORD="+st.GrafanaAdminPassword) ||
		!strings.Contains(string(b), "GF_SECURITY_SECRET_KEY="+st.GrafanaSecretKey) {
		t.Error("grafana.env does not carry the admin password and secret key")
	}
	if fi, _ := os.Stat(k.grafanaEnv()); fi.Mode().Perm() != 0o600 {
		t.Errorf("grafana.env is %v, want 0600", fi.Mode().Perm())
	}

	if env := kitEnv(st, "bench1.local"); strings.Contains(env, "GRAFANA_AUTH") {
		t.Error("kit.env names a Grafana login before the organisation exists")
	}
	st.DashboardOrg = 2
	env := kitEnv(st, "bench1.local")
	for _, want := range []string{
		"GRAFANA_URL=https://bench1.local:3000\n",
		"GRAFANA_AUTH=bench1:" + st.DashboardPassword + "\n",
		"GRAFANA_ORG_ID=2\n",
		"TF_VAR_grafana_org_id=2\n",
		"GRAFANA_CA_CERT=site-ca.pem\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("kit.env lacks %q", want)
		}
	}
}
