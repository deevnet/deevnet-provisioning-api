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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The card's own CA. It signs this Pi's server certificate and nothing else;
// an app trusts it the way it trusted site-ca.pem on Deevnet.
const (
	caValidity = 10 * 365 * 24 * time.Hour
	// 825 days is the longest server certificate Apple platforms accept, and
	// a Mac is the laptop most likely to be pointed at this Pi.
	serverValidity = 825 * 24 * time.Hour
)

func (k *kit) caKeyFile() string     { return filepath.Join(k.tlsDir(), "ca-key.pem") }
func (k *kit) serverFile() string    { return filepath.Join(k.tlsDir(), "server.pem") }
func (k *kit) serverKeyFile() string { return filepath.Join(k.tlsDir(), "server-key.pem") }

func (k *kit) issueCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	h, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "deevnet-kit CA " + h, Organization: []string{"deevnet-kit"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeKey(k.caKeyFile(), key); err != nil {
		return err
	}
	return writeFile(k.caFile(), pemBlock("CERTIFICATE", der), 0o644)
}

// issueServerCert signs a certificate for the names the Pi answers to: its
// mDNS name for laptops, its bare hostname, localhost for the bridge and the
// app's container, and its current addresses - because a Pico W cannot
// resolve a .local name, so a device dials the address and verifies it.
func (k *kit) issueServerCert() error {
	caCert, caKey, err := k.loadCA()
	if err != nil {
		return err
	}
	h, err := os.Hostname()
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dns, ips := serverNames(h)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: h + ".local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeKey(k.serverKeyFile(), key); err != nil {
		return err
	}
	// Mosquitto and vmauth read the key as their own users.
	if err := os.Chmod(k.serverKeyFile(), 0o640); err != nil {
		return err
	}
	if err := k.chown(k.serverKeyFile(), "root", tlsGroup); err != nil {
		return err
	}
	return writeFile(k.serverFile(), pemBlock("CERTIFICATE", der), 0o644)
}

func serverNames(h string) ([]string, []net.IP) {
	h = strings.TrimSuffix(h, ".local")
	return []string{h + ".local", h, "localhost"}, append([]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, localAddrs()...)
}

// localAddrs is every address a device on the owner's network could dial. A
// link-local address changes on its own and is left out.
func localAddrs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || !n.IP.IsGlobalUnicast() {
			continue
		}
		out = append(out, n.IP)
	}
	return out
}

// uncoveredAddrs is the addresses this Pi has now that its certificate does
// not name: a device dialling one of them would fail verification.
func (k *kit) uncoveredAddrs() ([]net.IP, error) {
	b, err := os.ReadFile(k.serverFile())
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("the server certificate holds no PEM block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, ip := range localAddrs() {
		covered := false
		for _, c := range cert.IPAddresses {
			if c.Equal(ip) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (k *kit) cmdRegenCerts() error {
	if _, err := k.loadState(); err != nil {
		return err
	}
	if err := k.issueServerCert(); err != nil {
		return err
	}
	if k.noExec {
		return nil
	}
	// Neither service re-reads its certificate on reload.
	return runCmd(append([]string{"systemctl", "restart"}, "mosquitto", "vmauth")...)
}

func (k *kit) loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(k.caFile())
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(k.caKeyFile())
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("the CA files hold no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("the CA key: %w", err)
	}
	return cert, key, nil
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, pemBlock("EC PRIVATE KEY", der), 0o600)
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return n
}
