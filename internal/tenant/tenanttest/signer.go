package tenanttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Signer stands in for the site's Tenant Service CA in the secret store. It
// holds a real three-tier hierarchy - a root, a Site CA and an issuing CA -
// and really signs, so what the service checks is a certificate and not a
// string.
//
// Like the role it stands in for, it takes a request's key and nothing else:
// the names are the ones it is handed.
type Signer struct {
	mu sync.Mutex

	// Calls is the names asked for, one entry per signing.
	Calls [][]string
	// Err, when set, is returned by every call: the secret store unreachable.
	Err error
	// Tamper, when set, changes the leaf before it is signed. It is how a test
	// makes the signer return something that was not asked for.
	Tamper func(leaf *x509.Certificate)
	// Now is the signer's clock.
	Now func() time.Time

	root, site, issuing          *x509.Certificate
	issuingKey                   *ecdsa.PrivateKey
	rootPEM, sitePEM, issuingPEM string
}

// NewSigner builds the hierarchy.
func NewSigner() *Signer {
	s := &Signer{Now: time.Now}
	rootKey := mustKey()
	s.root = mustCA("Deevnet Root CA", "Deevnet PKI", 2, nil, rootKey, rootKey)
	siteKey := mustKey()
	s.site = mustCA("Deevnet Mobile Site CA", "Mobile Site", 1, s.root, siteKey, rootKey)
	s.issuingKey = mustKey()
	s.issuing = mustCA("Deevnet Mobile Tenant Service CA", "Mobile Site", 0, s.site, s.issuingKey, siteKey)
	s.rootPEM, s.sitePEM, s.issuingPEM = certPEM(s.root), certPEM(s.site), certPEM(s.issuing)
	return s
}

// Roots is a pool holding the hierarchy's root alone, as a client would.
func (s *Signer) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.root)
	return pool
}

func (s *Signer) SignServer(_ context.Context, csrPEM string, names []string) (tenant.SignedCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return tenant.SignedCertificate{}, s.Err
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return tenant.SignedCertificate{}, errors.New("signer: no request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return tenant.SignedCertificate{}, err
	}
	s.Calls = append(s.Calls, append([]string(nil), names...))

	now := s.Now()
	leaf := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{Organization: []string{"Deevnet"}, OrganizationalUnit: []string{"Mobile Tenant Services"}, CommonName: names[0]},
		DNSNames:     append([]string(nil), names...),
		NotBefore:    now.Add(-30 * time.Second),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Never the request's own subject, names or extensions.
		BasicConstraintsValid: true,
	}
	if s.Tamper != nil {
		s.Tamper(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, s.issuing, csr.PublicKey, s.issuingKey)
	if err != nil {
		return tenant.SignedCertificate{}, err
	}
	return tenant.SignedCertificate{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		// The root comes too, as it can from a signer; the service drops it.
		Chain: []string{s.issuingPEM, s.sitePEM, s.rootPEM},
	}, nil
}

func mustKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func mustSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		panic(err)
	}
	return n
}

func mustCA(cn, ou string, pathLen int, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{Organization: []string{"Deevnet"}, OrganizationalUnit: []string{ou}, CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// Request makes a P-256 key and a signing request for it, as a tenant would.
// What the request says about itself - its subject and its names - is the
// caller's to choose, because the point of most tests is that it is ignored.
func Request(commonName string, dnsNames ...string) string {
	return RequestFor(mustKey(), commonName, dnsNames...)
}

// RequestFor makes a signing request for a key the caller holds, so that two
// requests can be for the same key.
func RequestFor(key any, commonName string, dnsNames ...string) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// NewKey is a P-256 key.
func NewKey() *ecdsa.PrivateKey { return mustKey() }
