package main

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ownerTools finds the ceremony tools: DEEVNET_PKI_OWNER_TOOLS, or the
// deevnet.mgmt checkout beside this repository, as on the Builder. CI has
// neither, and those tests skip.
func ownerTools(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("DEEVNET_PKI_OWNER_TOOLS")
	if dir == "" {
		dir, _ = filepath.Abs("../../../ansible-collection-deevnet.mgmt/scripts/pki")
	}
	if _, err := os.Stat(filepath.Join(dir, "deevnet-pki-owner.sh")); err != nil {
		t.Skipf("no deevnet-pki-owner.sh in %s (set DEEVNET_PKI_OWNER_TOOLS)", dir)
	}
	return dir
}

// ownerKit is an initialised card with the real tool, and a plain directory
// standing in for the stick: the tool's encryption check is the one thing
// these tests do not reach (scripts/pki tests it against LUKS).
func ownerKit(t *testing.T, cfg string) (*kit, string) {
	t.Helper()
	tools := ownerTools(t)
	k, _ := initKit(t, cfg)
	k.tool = filepath.Join(tools, "deevnet-pki-owner.sh")
	t.Setenv("DEEVNET_PKI_OWNER_PROFILE", filepath.Join(tools, "deevnet-pki-owner.cnf"))
	t.Setenv("PKI_OWNER_ROOT_PASS", "test-root-passphrase")
	t.Setenv("DEEVNET_PKI_OWNER_TEST_PLAIN_KEYS", "I know this is only a test")
	stick := filepath.Join(t.TempDir(), "stick")
	if err := os.MkdirAll(stick, 0o700); err != nil {
		t.Fatal(err)
	}
	return k, stick
}

func pool(t *testing.T, pemFile string) *x509.CertPool {
	t.Helper()
	b, err := os.ReadFile(pemFile)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		t.Fatalf("%s holds no certificate", pemFile)
	}
	return p
}

// The whole of ADR-0041 §4 on a card: init changes nothing served, export
// hands out both roots, switch moves everything here to the owner's, and a
// device given the bundle before the switch trusts the Pi after it.
func TestLeavingForAPKIOfYourOwn(t *testing.T) {
	k, stick := ownerKit(t, "tenant=mabell\nindex=3\n")
	if err := os.WriteFile(k.hostsFile(), []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cardCA, _ := os.ReadFile(k.caFile())
	serving, _ := os.ReadFile(k.serverFile())

	var out bytes.Buffer
	if err := k.cmdPKI(&out, []string{"init", "--org", "Mabell Home", "--domain", "home.example.com", "--keys", stick}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stick, "owner-root-ca.key")); err != nil {
		t.Fatal("the root key is not on the stick")
	}
	if _, err := os.Stat(filepath.Join(k.ownerDir(), "owner-root-ca.key")); err == nil {
		t.Fatal("the root key is on the Pi")
	}
	// Step 1: nothing served has changed.
	st, _ := k.loadState()
	if st.PKI != "" || st.OwnerOrg != "Mabell Home" || !slices.Equal(st.OwnerDomains, []string{"home.example.com"}) {
		t.Fatalf("state after init: %+v", st)
	}
	if now, _ := os.ReadFile(k.serverFile()); !bytes.Equal(now, serving) {
		t.Fatal("pki init changed the certificate this Pi serves")
	}
	if now, _ := os.ReadFile(k.caFile()); !bytes.Equal(now, cardCA) {
		t.Fatal("pki init changed what this Pi trusts")
	}

	// export hands out the bundle, and kit.env names it.
	dir := t.TempDir()
	if err := k.cmdExport([]string{dir}); err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "kit.env"))
	if !strings.Contains(string(env), "MQTT_CA_FILE="+trustBundleName) {
		t.Errorf("kit.env does not name the bundle:\n%s", env)
	}
	bundle := pool(t, filepath.Join(dir, trustBundleName))
	// A device given the bundle trusts the Pi as it is now...
	leaf, _ := serverCert(t, k)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: bundle, DNSName: mdnsName(t)}); err != nil {
		t.Fatalf("the bundle does not trust the certificate served before the switch: %v", err)
	}

	// Step 2.
	if err := k.cmdPKI(&out, []string{"switch"}); err != nil {
		t.Fatal(err)
	}
	st, _ = k.loadState()
	if !st.owner() {
		t.Fatal("the state does not say the owner's root")
	}
	if prev, _ := os.ReadFile(k.previousRootFile()); !bytes.Equal(prev, cardCA) {
		t.Error("the root trusted before was not kept")
	}
	root := filepath.Join(k.ownerDir(), ownerRootCert)
	inter := pool(t, filepath.Join(k.ownerDir(), ownerIssuingCert))
	leaf, trusted := serverCert(t, k)
	for _, name := range []string{mdnsName(t), "localhost", "127.0.0.1"} {
		opts := x509.VerifyOptions{Roots: trusted, Intermediates: inter, DNSName: name}
		if _, err := leaf.Verify(opts); err != nil {
			t.Errorf("what the services trust does not verify %s: %v", name, err)
		}
		// ...and the same bundle, unchanged, trusts it after.
		opts.Roots = bundle
		if _, err := leaf.Verify(opts); err != nil {
			t.Errorf("the bundle does not trust %s after the switch: %v", name, err)
		}
	}
	if h, _ := os.Hostname(); slices.Contains(leaf.DNSNames, h) {
		t.Error("the certificate names the bare host name, which the CA's constraints refuse")
	}
	if !strings.Contains(string(mustRead(t, k.serverKeyFile())), "PRIVATE KEY") {
		t.Error("no server key installed")
	}
	if hosts := string(mustRead(t, k.hostsFile())); strings.Contains(hosts, hostsBegin) || !strings.Contains(hosts, "127.0.0.1 localhost") {
		t.Errorf("hosts:\n%s", hosts)
	}
	if bridge := string(mustRead(t, k.bridgeEnv())); !strings.Contains(bridge, "ssl://localhost:8883") {
		t.Errorf("the bridge does not dial localhost:\n%s", bridge)
	}

	// Step 3: export hands out the owner's root alone.
	dir = t.TempDir()
	if err := k.cmdExport([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(dir, ownerRootExportName)); !bytes.Equal(got, mustRead(t, root)) {
		t.Error("export after the switch does not hand out the owner's root")
	}
	if env := string(mustRead(t, filepath.Join(dir, "kit.env"))); !strings.Contains(env, "MQTT_CA_FILE="+ownerRootExportName) {
		t.Errorf("kit.env after the switch:\n%s", env)
	}

	// Renewal on the Pi alone.
	before := mustRead(t, k.serverFile())
	k.noExec = true
	if err := k.cmdRegenCerts(); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, mustRead(t, k.serverFile())) {
		t.Error("regen-certs did not reissue")
	}
	leaf, _ = serverCert(t, k)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(t, root), Intermediates: inter, DNSName: mdnsName(t)}); err != nil {
		t.Errorf("the renewal does not verify: %v", err)
	}

	// A device, with a key of its own and from its own request.
	devs := t.TempDir()
	if err := k.cmdPKI(&out, []string{"enroll", "esp32-kitchen", "--out", devs}); err != nil {
		t.Fatal(err)
	}
	dev := parseOne(t, mustRead(t, filepath.Join(devs, "esp32-kitchen.pem")))
	if _, err := dev.Verify(x509.VerifyOptions{Roots: pool(t, filepath.Join(devs, ownerRootExportName)), Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || dev.Subject.CommonName != "esp32-kitchen" {
		t.Errorf("the device certificate: %v (%s)", err, dev.Subject)
	}
	if _, err := os.Stat(filepath.Join(devs, "esp32-kitchen.key")); err != nil {
		t.Error("no device key")
	}

	// A second init is refused before the tool runs.
	if err := k.cmdPKI(&out, []string{"init", "--org", "Mabell Home", "--keys", stick}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("a second init: %v", err)
	}
	if err := k.cmdPKI(&out, []string{"switch"}); err == nil {
		t.Error("a second switch was not refused")
	}
}

// V11 in miniature: the card is lost; a new card gets a new issuing CA from
// the stick, and what a device already trusts verifies the new card.
func TestANewCardFromTheStick(t *testing.T) {
	old, stick := ownerKit(t, "tenant=mabell\nindex=3\n")
	var out bytes.Buffer
	if err := old.cmdPKI(&out, []string{"init", "--org", "Mabell Home", "--keys", stick}); err != nil {
		t.Fatal(err)
	}
	deviceTrusts := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(deviceTrusts, mustRead(t, filepath.Join(old.ownerDir(), ownerRootCert)), 0o644); err != nil {
		t.Fatal(err)
	}

	card, _ := ownerKit(t, "tenant=mabell\nindex=3\n")
	out.Reset()
	if err := card.cmdPKI(&out, []string{"issuing", "--org", "Mabell Home", "--keys", stick}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), trustBundleName) || !strings.Contains(out.String(), "pki switch") {
		t.Errorf("a new card's next step is pki switch, not the bundle:\n%s", out.String())
	}
	if err := card.cmdPKI(&out, []string{"switch"}); err != nil {
		t.Fatal(err)
	}
	oldIssuing := mustRead(t, filepath.Join(old.ownerDir(), ownerIssuingCert))
	newIssuing := mustRead(t, filepath.Join(card.ownerDir(), ownerIssuingCert))
	if bytes.Equal(oldIssuing, newIssuing) {
		t.Fatal("the new card has the old card's issuing CA")
	}
	leaf, _ := serverCert(t, card)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(t, deviceTrusts),
		Intermediates: pool(t, filepath.Join(card.ownerDir(), ownerIssuingCert)), DNSName: mdnsName(t)}); err != nil {
		t.Errorf("a device's root does not verify the new card: %v", err)
	}
}

// A Deevnet Pi leaves too (V8): its devices verify mqtt.<tenant>.deevnet.net,
// and the owner's CA may sign that, so the name survives the switch. A device
// given the bundle before it verifies the same name on both certificates, and
// only its root changes. A Deevnet name outside the tenant's is still left out.
func TestADeevnetPiLeaves(t *testing.T) {
	tools := ownerTools(t)
	ca := newTestCA(t)
	k, _ := becomeDeevnetPi(t, ca)
	k.tool = filepath.Join(tools, "deevnet-pki-owner.sh")
	t.Setenv("DEEVNET_PKI_OWNER_PROFILE", filepath.Join(tools, "deevnet-pki-owner.cnf"))
	t.Setenv("PKI_OWNER_ROOT_PASS", "test-root-passphrase")
	t.Setenv("DEEVNET_PKI_OWNER_TEST_PLAIN_KEYS", "I know this is only a test")
	stick := t.TempDir()
	if err := k.writeNames([]string{"console.eds.deevnet.net", "grafana.mobile.deevnet.net", "192.168.7.20"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := k.cmdPKI(&out, []string{"init", "--org", "EdS", "--keys", stick}); err != nil {
		t.Fatal(err)
	}
	st, _ := k.loadState()
	if !slices.Equal(st.OwnerDomains, []string{"eds.deevnet.net"}) {
		t.Fatalf("a Deevnet Pi's owner CA must be permitted its tenant's names: %v", st.OwnerDomains)
	}
	issuing := parseOne(t, mustRead(t, filepath.Join(k.ownerDir(), ownerIssuingCert)))
	if !slices.Contains(issuing.PermittedDNSDomains, "eds.deevnet.net") || slices.Contains(issuing.PermittedDNSDomains, "deevnet.net") {
		t.Fatalf("the issuing CA permits %v", issuing.PermittedDNSDomains)
	}

	// Step 1: the device is given the bundle while the Deevnet certificate serves.
	dir := t.TempDir()
	if err := k.cmdExport([]string{dir}); err != nil {
		t.Fatal(err)
	}
	bundlePEM := string(mustRead(t, filepath.Join(dir, trustBundleName)))
	if !strings.Contains(bundlePEM, strings.TrimSpace(string(ca.rootPEM))) || strings.Count(bundlePEM, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("the bundle does not hold the Deevnet Root and the owner's:\n%s", bundlePEM)
	}
	bundle := pool(t, filepath.Join(dir, trustBundleName))
	deevnetInter := x509.NewCertPool()
	deevnetInter.AddCert(ca.issuing)
	leaf, _ := serverCert(t, k)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: bundle, Intermediates: deevnetInter, DNSName: "mqtt.eds.deevnet.net"}); err != nil {
		t.Fatalf("before the switch, the device's name does not verify on the bundle: %v", err)
	}

	// Step 2.
	if err := k.cmdPKI(&out, []string{"switch"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "still answers to its names under eds.deevnet.net") ||
		!strings.Contains(out.String(), "left out grafana.mobile.deevnet.net") {
		t.Errorf("switch said:\n%s", out.String())
	}
	st, _ = k.loadState()
	if !st.keepsTenantNames() {
		t.Fatal("the state does not keep the tenant's names")
	}
	ownerInter := pool(t, filepath.Join(k.ownerDir(), ownerIssuingCert))
	leaf, trusted := serverCert(t, k)
	for _, name := range []string{"mqtt.eds.deevnet.net", "logs.eds.deevnet.net", "grafana.eds.deevnet.net", "console.eds.deevnet.net"} {
		// The same bundle and the same name, after the switch.
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: bundle, Intermediates: ownerInter, DNSName: name}); err != nil {
			t.Errorf("after the switch, %s does not verify on the bundle: %v", name, err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: trusted, Intermediates: ownerInter, DNSName: name}); err != nil {
			t.Errorf("what the services trust does not verify %s: %v", name, err)
		}
	}
	if slices.Contains(leaf.DNSNames, "grafana.mobile.deevnet.net") || !slices.ContainsFunc(leaf.IPAddresses, net.ParseIP("192.168.7.20").Equal) {
		t.Errorf("names %v, addresses %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if prev := mustRead(t, k.previousRootFile()); !bytes.Equal(prev, ca.rootPEM) {
		t.Error("the Deevnet Root was not kept as the previous root")
	}
	if hosts := string(mustRead(t, k.hostsFile())); !strings.Contains(hosts, "127.0.0.1 mqtt.eds.deevnet.net logs.eds.deevnet.net grafana.eds.deevnet.net") {
		t.Errorf("the services' names are not mapped:\n%s", hosts)
	}
	if bridge := string(mustRead(t, k.bridgeEnv())); !strings.Contains(bridge, "ssl://mqtt.eds.deevnet.net:8883") {
		t.Errorf("the bridge does not dial the kept name:\n%s", bridge)
	}
	// Step 3: the owner's root alone, and an app's env keeps the same hosts.
	dir = t.TempDir()
	if err := k.cmdExport([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if env := string(mustRead(t, filepath.Join(dir, "kit.env"))); !strings.Contains(env, "MQTT_HOST=mqtt.eds.deevnet.net") ||
		!strings.Contains(env, "MQTT_CA_FILE="+ownerRootExportName) {
		t.Errorf("kit.env after the switch:\n%s", env)
	}
}

func TestPKIRefusesBeforeTheTool(t *testing.T) {
	k, _ := initKit(t, "tenant=pi\n")
	k.tool = "/nonexistent/deevnet-pki-owner.sh"
	var out bytes.Buffer
	for _, args := range [][]string{
		{"init"},                                 // no --org
		{"switch"},                               // no CA yet
		{"enroll", "dev1", "--out", t.TempDir()}, // no CA yet
		{"enroll", "--out", "x"},                 // no device
		{"init", "--org", "X", "extra"},          // stray argument
		{"bogus"},
	} {
		if err := k.cmdPKI(&out, args); err == nil || strings.Contains(err.Error(), "nonexistent") {
			t.Errorf("pki %v: %v", args, err)
		}
	}
}

func TestOwnerServerNames(t *testing.T) {
	addrs := []net.IP{net.ParseIP("192.168.1.50"), net.ParseIP("203.0.113.9"), net.ParseIP("fd00::5")}
	extra := []string{"pi.home.example.com", "home.example.com", "mqtt.eds.deevnet.net", "10.1.2.3", "8.8.8.8", "other.local", "evilhome.example.com"}
	names, dropped := ownerServerNames("mabellpi", addrs, extra, []string{"home.example.com"}, "mabell.deevnet.net")
	want := []string{"mabellpi.local", "localhost", "127.0.0.1", "::1", "192.168.1.50", "fd00::5",
		"pi.home.example.com", "home.example.com", "10.1.2.3", "other.local"}
	if !slices.Equal(names, want) {
		t.Errorf("names\n got %v\nwant %v", names, want)
	}
	if !slices.Equal(dropped, []string{"mqtt.eds.deevnet.net", "8.8.8.8", "evilhome.example.com"}) {
		t.Errorf("dropped %v", dropped)
	}
	// With the tenant's domain permitted, the kit's services keep their names.
	names, dropped = ownerServerNames("mabellpi", nil, []string{"mqtt.eds.deevnet.net", "www.mabell.deevnet.net"},
		[]string{"mabell.deevnet.net"}, "mabell.deevnet.net")
	want = []string{"mabellpi.local", "localhost", "127.0.0.1", "::1",
		"mqtt.mabell.deevnet.net", "logs.mabell.deevnet.net", "grafana.mabell.deevnet.net", "www.mabell.deevnet.net"}
	if !slices.Equal(names, want) || !slices.Equal(dropped, []string{"mqtt.eds.deevnet.net"}) {
		t.Errorf("names %v, dropped %v", names, dropped)
	}
}

// mdnsName is <host>.local for the machine the tests run on: the kit names
// the Pi's real host name.
func mdnsName(t *testing.T) string {
	h, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	return h + ".local"
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseOne(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	certs, err := parseCerts(b)
	if err != nil {
		t.Fatal(err)
	}
	return certs[0]
}
