package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A Deevnet Pi (ADR-0041 §2): its server certificate is the Tenant Service
// CA's, for the tenant's site-less names, and everything on it trusts the
// Deevnet Root. The Pi makes the key and a request; the Mobile Factory signs
// it in a work session; the Pi installs what comes back. The key never leaves
// the Pi, and no CA key is on it.
//
// A card starts on its own CA, as every card does, and becomes a Deevnet Pi
// when a certificate is installed. Its own services then dial its names,
// mapped to loopback here, so the certificate needs neither localhost nor an
// address, and an app is handed the names and the root.

const (
	pkiDeevnet = "deevnet"
	rootDomain = "deevnet.net"
	// rootExportName is the name export gives the Deevnet Root, and the name
	// kit.env points the app at: the name every Deevnet client already uses.
	rootExportName = "deevnet-root-ca.pem"
)

// kitServices are the labels the kit's own services answer to. A Deevnet
// certificate must name each of them, site-less, or a service on this Pi
// would fail to verify another.
var kitServices = []string{"mqtt", "logs", "grafana"}

func (st state) deevnet() bool { return st.PKI == pkiDeevnet }

// name is what this Pi's own services dial for svc: its Deevnet name, mapped
// to loopback, on a Deevnet Pi, and localhost on its own CA.
func (st state) name(svc string) string {
	if st.deevnet() {
		return svc + "." + st.Tenant + "." + rootDomain
	}
	return "localhost"
}

// appHost is what an app or a device dials for svc: the Deevnet name, which
// the network's DNS answers, or the Pi's mDNS name on its own CA.
func (st state) appHost(svc, mdns string) string {
	if st.deevnet() {
		return st.name(svc)
	}
	return mdns
}

func (st state) caExportName() string {
	if st.deevnet() {
		return rootExportName
	}
	return kitCAExportName
}

func (k *kit) requestKeyFile() string { return filepath.Join(k.tlsDir(), "request-key.pem") }
func (k *kit) requestFile() string    { return filepath.Join(k.tlsDir(), "server.csr") }
func (k *kit) cardCAFile() string     { return filepath.Join(k.tlsDir(), "card-ca.pem") }
func (k *kit) hostsFile() string      { return k.p("/etc/hosts") }

func (k *kit) cmdCert(w io.Writer, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "request":
		return k.certRequest(w)
	case len(args) == 3 && args[0] == "install":
		return k.certInstall(args[1], args[2])
	}
	return errors.New("cert request | cert install FULLCHAIN ROOT")
}

// certRequest makes a new key, kept beside the certificate it will replace
// until one is installed for it, and a request, which is public and may
// travel. Its names are not read by the API, which builds them; they are
// there for whoever looks at the file.
func (k *kit) certRequest(w io.Writer) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var dns []string
	for _, s := range kitServices {
		dns = append(dns, s+"."+st.Tenant+"."+rootDomain)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dns[0]},
		DNSNames: dns,
	}, key)
	if err != nil {
		return err
	}
	if err := writeKey(k.requestKeyFile(), key); err != nil {
		return err
	}
	csr := pemBlock("CERTIFICATE REQUEST", der)
	if err := writeFile(k.requestFile(), csr, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "# %s: have the Tenant Service CA sign this for tenant %s, with names %s\n",
		k.requestFile(), st.Tenant, strings.Join(kitServices[1:], ", "))
	_, err = w.Write(csr)
	return err
}

// certInstall checks what came back before anything is touched: it is for the
// requested key, it chains to the root given, and it names every service
// here. Then it becomes the server certificate, the root becomes what every
// service trusts, and the card is a Deevnet Pi.
func (k *kit) certInstall(fullchainPath, rootPath string) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	fullchain, err := os.ReadFile(fullchainPath)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		return err
	}
	certs, err := parseCerts(fullchain)
	if err != nil {
		return fmt.Errorf("%s: %w", fullchainPath, err)
	}
	roots, err := parseCerts(rootPEM)
	if err != nil || len(roots) != 1 || !roots[0].IsCA {
		return fmt.Errorf("%s must be one CA certificate: the Deevnet Root", rootPath)
	}
	keyPEM, err := os.ReadFile(k.requestKeyFile())
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no request is pending: run deevnet-kit cert request, and have that signed")
	}
	if err != nil {
		return err
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return err
	}
	leaf := certs[0]
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("the certificate is not for the pending request's key")
	}
	rootPool, inter := x509.NewCertPool(), x509.NewCertPool()
	rootPool.AddCert(roots[0])
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	var missing []string
	for _, s := range kitServices {
		n := s + "." + st.Tenant + "." + rootDomain
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: rootPool, Intermediates: inter, DNSName: n,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the certificate does not verify against the root for %s: ask for it with names %s",
			strings.Join(missing, ", "), strings.Join(kitServices[1:], ", "))
	}

	// The card's own CA is kept, so going back is a copy.
	if !st.deevnet() {
		if ca, err := os.ReadFile(k.caFile()); err == nil {
			if err := writeFile(k.cardCAFile(), ca, 0o644); err != nil {
				return err
			}
		}
	}
	if err := writeFile(k.serverKeyFile(), keyPEM, 0o640); err != nil {
		return err
	}
	if err := k.chown(k.serverKeyFile(), "root", tlsGroup); err != nil {
		return err
	}
	if err := writeFile(k.serverFile(), fullchain, 0o644); err != nil {
		return err
	}
	if err := writeFile(k.caFile(), rootPEM, 0o644); err != nil {
		return err
	}
	if err := os.Remove(k.requestKeyFile()); err != nil {
		return err
	}
	st.PKI = pkiDeevnet
	if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
		return err
	}
	if err := k.writeHosts(st); err != nil {
		return err
	}
	if err := k.writeBridgeEnv(st); err != nil {
		return err
	}
	fmt.Printf("installed: %s, valid to %s; this Pi now answers as %s\n",
		leaf.Subject.CommonName, leaf.NotAfter.Format("2006-01-02"), strings.Join(leaf.DNSNames, ", "))
	fmt.Println("an app's kit.env changes: deevnet-kit export again, with deevnet-root-ca.pem")
	if k.noExec {
		return nil
	}
	return runCmd("systemctl", "restart", "mosquitto", "vmauth", "grafana", "deevnet-log-bridge")
}

const hostsBegin, hostsEnd = "# BEGIN deevnet-kit", "# END deevnet-kit"

// writeHosts maps this Pi's own names to loopback, so its services reach one
// another by the names the certificate holds. Everything outside the block is
// left as it was.
func (k *kit) writeHosts(st state) error {
	old, err := os.ReadFile(k.hostsFile())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var keep []string
	skip := false
	for _, line := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		switch {
		case line == hostsBegin:
			skip = true
		case line == hostsEnd:
			skip = false
		case !skip && line != "":
			keep = append(keep, line)
		}
	}
	var names []string
	for _, s := range kitServices {
		names = append(names, st.name(s))
	}
	keep = append(keep, hostsBegin, "127.0.0.1 "+strings.Join(names, " "), hostsEnd)
	return writeFile(k.hostsFile(), []byte(strings.Join(keep, "\n")+"\n"), 0o644)
}

func parseCerts(in []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, in = pem.Decode(in)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("holds a %s, not only certificates", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("holds no certificate")
	}
	return out, nil
}

func parseECKey(in []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, errors.New("the pending key is not PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the pending key is not ECDSA")
	}
	return key, nil
}
