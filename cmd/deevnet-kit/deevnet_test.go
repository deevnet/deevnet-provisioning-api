package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA is a root and an issuing CA under it: the Deevnet Root and the
// Tenant Service CA, as far as the kit can tell.
type testCA struct {
	root, issuing       *x509.Certificate
	rootKey, issuingKey *ecdsa.PrivateKey
	rootPEM, chainPEM   []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key, pemBlock("CERTIFICATE", der)
	}
	root, rootKey, rootPEM := mk("Test Root", nil, nil)
	issuing, issuingKey, chainPEM := mk("Test Tenant Service CA", root, rootKey)
	return testCA{root, issuing, rootKey, issuingKey, rootPEM, chainPEM}
}

// sign issues a leaf for the request's key with names, and returns the full
// chain a server presents.
func (ca testCA) sign(t *testing.T, csrPEM []byte, names ...string) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca.issuing, csr.PublicKey, ca.issuingKey)
	if err != nil {
		t.Fatal(err)
	}
	return append(pemBlock("CERTIFICATE", der), ca.chainPEM...)
}

func writeTemp(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

var edsNames = []string{"mqtt.eds.deevnet.net", "logs.eds.deevnet.net", "grafana.eds.deevnet.net",
	"console.eds.deevnet.net", "mqtt.eds.home.deevnet.net"}

// The whole move: a request, the factory's certificate for it, and after
// install every service here dials and trusts the Deevnet names and root.
func TestACardBecomesADeevnetPi(t *testing.T) {
	k, _ := initKit(t, "tenant=eds\nindex=2\n")
	ca := newTestCA(t)
	if err := os.WriteFile(k.hostsFile(), []byte("127.0.0.1 localhost\n::1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cardCA, _ := os.ReadFile(k.caFile())

	var out bytes.Buffer
	if err := k.cmdCert(&out, []string{"request"}); err != nil {
		t.Fatal(err)
	}
	csr, _ := os.ReadFile(k.requestFile())
	if !strings.Contains(out.String(), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("the request was not printed: %s", out.String())
	}
	// Until it is installed, nothing the services use has changed.
	if st, _ := k.loadState(); st.deevnet() {
		t.Fatal("a request alone made the card a Deevnet Pi")
	}

	full := writeTemp(t, "fullchain.pem", ca.sign(t, csr, edsNames...))
	root := writeTemp(t, "root.pem", ca.rootPEM)
	if err := k.cmdCert(&out, []string{"install", full, root}); err != nil {
		t.Fatal(err)
	}

	st, _ := k.loadState()
	if !st.deevnet() {
		t.Fatal("the state does not say it is a Deevnet Pi")
	}
	if got, _ := os.ReadFile(k.caFile()); !bytes.Equal(got, ca.rootPEM) {
		t.Error("the services do not trust the root")
	}
	if got, _ := os.ReadFile(k.cardCAFile()); !bytes.Equal(got, cardCA) {
		t.Error("the card's own CA was not kept")
	}
	if _, err := os.Stat(k.requestKeyFile()); !os.IsNotExist(err) {
		t.Error("the pending key is still there")
	}
	leaf, pool := serverCert(t, k)
	inter := x509.NewCertPool()
	inter.AddCert(ca.issuing)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: "mqtt.eds.deevnet.net"}); err != nil {
		t.Errorf("the server certificate does not verify against what the services trust: %v", err)
	}

	hosts, _ := os.ReadFile(k.hostsFile())
	if !strings.Contains(string(hosts), "127.0.0.1 localhost") ||
		!strings.Contains(string(hosts), "127.0.0.1 mqtt.eds.deevnet.net logs.eds.deevnet.net grafana.eds.deevnet.net") {
		t.Errorf("hosts:\n%s", hosts)
	}
	bridge, _ := os.ReadFile(k.bridgeEnv())
	for _, want := range []string{"ssl://mqtt.eds.deevnet.net:8883", "https://logs.eds.deevnet.net:8427"} {
		if !strings.Contains(string(bridge), want) {
			t.Errorf("the bridge does not dial %s:\n%s", want, bridge)
		}
	}
	env := kitEnv(st, "eds-backend.local", appCreds{})
	for _, want := range []string{"MQTT_HOST=mqtt.eds.deevnet.net", "MQTT_CA_FILE=deevnet-root-ca.pem",
		"LOG_ENDPOINT=https://logs.eds.deevnet.net:8427"} {
		if !strings.Contains(env, want) {
			t.Errorf("kit.env has no %s:\n%s", want, env)
		}
	}

	// export hands an app the root under the name every Deevnet client uses.
	dir := t.TempDir()
	if err := k.cmdExport([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, rootExportName)); !bytes.Equal(got, ca.rootPEM) {
		t.Error("export did not write the root")
	}

	// regen-certs would put the card's CA back under everything.
	if err := k.cmdRegenCerts(); err == nil {
		t.Error("regen-certs ran on a Deevnet Pi")
	}

	// Installing again rewrites the block, not adds another.
	if err := k.cmdCert(&out, []string{"request"}); err != nil {
		t.Fatal(err)
	}
	csr, _ = os.ReadFile(k.requestFile())
	if err := k.cmdCert(&out, []string{"install", writeTemp(t, "f2.pem", ca.sign(t, csr, edsNames...)), root}); err != nil {
		t.Fatal(err)
	}
	if hosts, _ := os.ReadFile(k.hostsFile()); strings.Count(string(hosts), hostsBegin) != 1 {
		t.Errorf("a second install added a second block:\n%s", hosts)
	}
}

// Nothing is installed that would leave a service unable to verify another,
// or that is not for the key this Pi holds.
func TestInstallRefuses(t *testing.T) {
	k, _ := initKit(t, "tenant=eds\nindex=2\n")
	ca, other := newTestCA(t), newTestCA(t)
	root := writeTemp(t, "root.pem", ca.rootPEM)
	var out bytes.Buffer

	if err := k.cmdCert(&out, []string{"install", writeTemp(t, "f.pem", ca.chainPEM), root}); err == nil ||
		!strings.Contains(err.Error(), "no request is pending") {
		t.Errorf("no request: %v", err)
	}
	if err := k.cmdCert(&out, []string{"request"}); err != nil {
		t.Fatal(err)
	}
	csr, _ := os.ReadFile(k.requestFile())
	before, _ := os.ReadFile(k.serverFile())

	// Another key: a request this Pi did not make.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	foreign := pemBlock("CERTIFICATE REQUEST", der)

	for why, full := range map[string][]byte{
		"another key":           ca.sign(t, foreign, edsNames...),
		"a name missing":        ca.sign(t, csr, "mqtt.eds.deevnet.net", "logs.eds.deevnet.net"),
		"another tenant's":      ca.sign(t, csr, "mqtt.tdemo.deevnet.net", "logs.tdemo.deevnet.net", "grafana.tdemo.deevnet.net"),
		"another root's":        other.sign(t, csr, edsNames...),
		"only the site's names": ca.sign(t, csr, "mqtt.eds.home.deevnet.net", "logs.eds.home.deevnet.net", "grafana.eds.home.deevnet.net"),
	} {
		if err := k.cmdCert(&out, []string{"install", writeTemp(t, "f.pem", full), root}); err == nil {
			t.Errorf("%s: installed", why)
		}
	}
	if after, _ := os.ReadFile(k.serverFile()); !bytes.Equal(before, after) {
		t.Error("a refused install changed the server certificate")
	}
	if st, _ := k.loadState(); st.deevnet() {
		t.Error("a refused install made the card a Deevnet Pi")
	}
}

// A card on its own CA is as it was: localhost for its services, its mDNS name
// and its CA for an app.
func TestACardOnItsOwnCAIsUnchanged(t *testing.T) {
	k, st := initKit(t, "tenant=eds\nindex=2\n")
	env := kitEnv(st, "eds-backend.local", appCreds{})
	for _, want := range []string{"MQTT_HOST=eds-backend.local", "MQTT_CA_FILE=deevnet-kit-ca.pem"} {
		if !strings.Contains(env, want) {
			t.Errorf("kit.env has no %s", want)
		}
	}
	bridge, _ := os.ReadFile(k.bridgeEnv())
	if !strings.Contains(string(bridge), "ssl://localhost:8883") {
		t.Errorf("bridge:\n%s", bridge)
	}
}
