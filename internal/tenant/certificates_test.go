package tenant_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func leafOf(t *testing.T, c tenant.Certificate) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(c.PEM))
	if block == nil {
		t.Fatalf("no certificate in %q", c.PEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func isInvalid(err error) bool {
	var inv *tenant.InvalidError
	return errors.As(err, &inv)
}

func isStep(err error, step string) bool {
	var se *tenant.StepError
	return errors.As(err, &se) && se.Step == step
}

// The certificate is for a name in the caller's zone, and a client that holds
// only the root can verify it with what comes back.
func TestACertificateIsForANameInTheTenantsZone(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")

	c, issued, err := svc.PutCertificate(context.Background(), "eds", "console",
		tenant.CertificateRequest{CSR: tenanttest.Request("anything")})
	if err != nil {
		t.Fatal(err)
	}
	if !issued {
		t.Error("the first request did not report a new certificate")
	}
	// Its name wherever it runs, then its name at this site (ADR-0040 §3).
	if strings.Join(c.Names, ",") != "console.eds.deevnet.net,console.eds.mobile.deevnet.net" {
		t.Fatalf("names = %v", c.Names)
	}
	leaf := leafOf(t, c)
	if leaf.Subject.CommonName != "console.eds.deevnet.net" {
		t.Errorf("common name = %q", leaf.Subject.CommonName)
	}

	// The chain is what a server presents after the leaf: two CAs, no root.
	intermediates := x509.NewCertPool()
	if !intermediates.AppendCertsFromPEM([]byte(c.Chain)) {
		t.Fatal("the chain holds no certificate")
	}
	if n := strings.Count(c.Chain, "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("the chain holds %d certificates, want the issuing CA and the Site CA", n)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: b.Signer.Roots(), Intermediates: intermediates,
		DNSName: "console.eds.deevnet.net", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("a client holding only the root cannot verify it: %v", err)
	}
	if c.RenewAfter() != c.NotAfter.Add(-60*24*time.Hour) {
		t.Errorf("renew after %s, not after %s", c.RenewAfter(), c.NotAfter)
	}
}

// Certificates standard 4.6. The request is read for its key. A tenant that
// writes a substrate name into its request gets a certificate for its own.
func TestWhatTheRequestSaysAboutItselfIsIgnored(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")

	csr := tenanttest.Request("grafana.mobile.deevnet.net", "api.mobile.deevnet.net", "*.mobile.deevnet.net", "example.com")
	c, _, err := svc.PutCertificate(context.Background(), "eds", "console", tenant.CertificateRequest{CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, c)
	if strings.Join(leaf.DNSNames, ",") != "console.eds.deevnet.net,console.eds.mobile.deevnet.net" {
		t.Fatalf("the certificate is valid for %v", leaf.DNSNames)
	}
	// And the signer was never handed the request's names to consider.
	if got := b.Signer.Calls[0]; len(got) != 2 || got[0] != "console.eds.deevnet.net" {
		t.Fatalf("the signer was asked for %v", got)
	}
}

func TestFurtherNamesAreLabelsInTheSameZone(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")

	c, _, err := svc.PutCertificate(context.Background(), "eds", "console",
		tenant.CertificateRequest{CSR: tenanttest.Request("x"), Names: []string{"www", "lightd"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"console.eds.deevnet.net", "www.eds.deevnet.net", "lightd.eds.deevnet.net",
		"console.eds.mobile.deevnet.net", "www.eds.mobile.deevnet.net", "lightd.eds.mobile.deevnet.net"}
	if strings.Join(c.Names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", c.Names, want)
	}
}

// A tenant sends labels and never a name, so there is no way to spell a zone
// that is not its own.
func TestANameThatIsNotOneLabelIsRefused(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	csr := tenanttest.Request("x")

	for _, name := range []string{
		"", "Console", "console.", "console.eds.mobile.deevnet.net", "grafana.mobile", "a.b",
		"*", "*.eds", "-console", "console-", "con sole", "console/../x", strings.Repeat("a", 21),
	} {
		if _, _, err := svc.PutCertificate(ctx, "eds", name, tenant.CertificateRequest{CSR: csr}); !isInvalid(err) {
			t.Errorf("certificate name %q: %v", name, err)
		}
		if _, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: csr, Names: []string{name}}); !isInvalid(err) {
			t.Errorf("further name %q: %v", name, err)
		}
	}
	for _, names := range [][]string{
		{"console"},                              // its own name again
		{"www", "www"},                           // twice
		{"a", "b", "c", "d", "e", "f", "g", "h"}, // nine with its own
	} {
		if _, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: csr, Names: names}); !isInvalid(err) {
			t.Errorf("names %v: %v", names, err)
		}
	}
	if len(b.Signer.Calls) != 0 {
		t.Fatalf("the signer was reached %d times by requests that should have been refused", len(b.Signer.Calls))
	}
}

func TestTheSameQuestionGetsTheSameCertificate(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	key := tenanttest.NewKey()
	req := tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x"), Names: []string{"www"}}

	first, _, err := svc.PutCertificate(ctx, "eds", "console", req)
	if err != nil {
		t.Fatal(err)
	}
	// A request is re-made by every apply, and no two encodings of one are
	// the same bytes. It is the key that makes it the same question.
	again := tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "something else"), Names: []string{"www"}}
	second, issued, err := svc.PutCertificate(ctx, "eds", "console", again)
	if err != nil {
		t.Fatal(err)
	}
	if issued || second.Serial != first.Serial || second.PEM != first.PEM {
		t.Fatalf("asking again issued another: %s then %s", first.Serial, second.Serial)
	}
	if len(b.Signer.Calls) != 1 {
		t.Fatalf("the signer was asked %d times", len(b.Signer.Calls))
	}
}

func TestANewKeyOrAChangedNameIsANewCertificate(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	key := tenanttest.NewKey()

	first, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x")})
	if err != nil {
		t.Fatal(err)
	}
	renamed, issued, err := svc.PutCertificate(ctx, "eds", "console",
		tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x"), Names: []string{"www"}})
	if err != nil || !issued || renamed.Serial == first.Serial {
		t.Fatalf("a changed name: issued=%v err=%v", issued, err)
	}
	rekeyed, issued, err := svc.PutCertificate(ctx, "eds", "console",
		tenant.CertificateRequest{CSR: tenanttest.Request("x"), Names: []string{"www"}})
	if err != nil || !issued || rekeyed.KeyFingerprint == renamed.KeyFingerprint {
		t.Fatalf("a new key: issued=%v err=%v", issued, err)
	}
	// One certificate per name: the registry holds the current one.
	held, _ := svc.ListCertificates(ctx, "eds")
	if len(held) != 1 || held[0].Serial != rekeyed.Serial {
		t.Fatalf("the registry holds %+v", held)
	}
}

// Certificates standard 4.7: reissued once fewer than 60 days remain.
func TestACertificateCloseToExpiryIsReissued(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	key := tenanttest.NewKey()
	req := func() tenant.CertificateRequest {
		return tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x")}
	}

	clock := time.Now()
	svc.Now = func() time.Time { return clock }
	b.Signer.Now = func() time.Time { return clock }

	first, _, err := svc.PutCertificate(ctx, "eds", "console", req())
	if err != nil {
		t.Fatal(err)
	}

	clock = first.NotAfter.Add(-61 * 24 * time.Hour)
	if _, issued, _ := svc.PutCertificate(ctx, "eds", "console", req()); issued {
		t.Fatal("reissued with 61 days left")
	}
	clock = first.NotAfter.Add(-59 * 24 * time.Hour)
	second, issued, err := svc.PutCertificate(ctx, "eds", "console", req())
	if err != nil || !issued {
		t.Fatalf("not reissued with 59 days left: issued=%v err=%v", issued, err)
	}
	if !second.NotAfter.After(first.NotAfter) || second.KeyFingerprint != first.KeyFingerprint {
		t.Fatalf("the reissue runs to %s, the first to %s", second.NotAfter, first.NotAfter)
	}
}

func TestARequestThatIsNotOneGoodRequestIsRefused(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	good := tenanttest.Request("x")

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A request whose signature is not its key's: the body of one, with the
	// last byte of its signature changed.
	block, _ := pem.Decode([]byte(good))
	forged := append([]byte(nil), block.Bytes...)
	forged[len(forged)-1] ^= 0xff

	for name, csr := range map[string]string{
		"nothing":             "",
		"not PEM":             "a certificate, please",
		"a certificate":       strings.ReplaceAll(good, "CERTIFICATE REQUEST", "CERTIFICATE"),
		"a private key":       "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"two requests":        good + tenanttest.Request("y"),
		"something after it":  good + "and a note",
		"PEM around nonsense": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
		"a forged signature":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: forged})),
		"a 1024-bit RSA key":  tenanttest.RequestFor(weak, "x"),
		"a P-384 key":         tenanttest.RequestFor(p384, "x"),
		"an Ed25519 key":      tenanttest.RequestFor(ed, "x"),
	} {
		_, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: csr})
		if !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(b.Signer.Calls) != 0 {
		t.Fatalf("the signer was reached %d times", len(b.Signer.Calls))
	}
}

func TestAnRSARequestIsTaken(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.PutCertificate(context.Background(), "eds", "console",
		tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x")}); err != nil {
		t.Fatal(err)
	}
}

// The signer is trusted to sign, not to be right. What it returns is held to
// what was asked before a tenant, or the registry, is given it.
func TestACertificateThatWasNotAskedForIsRefused(t *testing.T) {
	for name, tamper := range map[string]func(*x509.Certificate){
		"another name beside it": func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "grafana.mobile.deevnet.net") },
		"another name instead":   func(c *x509.Certificate) { c.DNSNames = []string{"grafana.mobile.deevnet.net"} },
		"another common name":    func(c *x509.Certificate) { c.Subject.CommonName = "grafana.mobile.deevnet.net" },
		"an address":             func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("10.20.25.21")} },
		"a URI": func(c *x509.Certificate) {
			c.URIs = []*url.URL{{Scheme: "urn", Opaque: "deevnet:mobile:tenant:eds:device:x"}}
		},
		"a CA":                  func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"client authentication": func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) },
		"no usage at all":       func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"two years":             func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(2 * 365 * 24 * time.Hour) },
		"already expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc, _, b := tenanttest.NewService()
			ready(t, svc, "eds")
			b.Signer.Tamper = tamper

			c, issued, err := svc.PutCertificate(context.Background(), "eds", "console",
				tenant.CertificateRequest{CSR: tenanttest.Request("x")})
			if !isStep(err, tenant.StepCertificate) {
				t.Fatalf("err = %v", err)
			}
			if issued || c.PEM != "" {
				t.Fatal("the certificate was handed back anyway")
			}
			if _, err := svc.GetCertificate(context.Background(), "eds", "console"); !errors.Is(err, tenant.ErrNotFound) {
				t.Fatalf("it was kept: %v", err)
			}
		})
	}
}

func TestASignerThatCannotBeReachedIsAFailedStepThatNamesNothing(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ready(t, svc, "eds")
	b.Signer.Err = fmt.Errorf("Post https://10.20.25.21:8200/v1/pki-tenant-service/sign/tenant-service: connection refused")

	_, _, err := svc.PutCertificate(context.Background(), "eds", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")})
	if !isStep(err, tenant.StepCertificate) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "10.20.25.21") || strings.Contains(err.Error(), "pki-") {
		t.Fatalf("the error a caller sees names the backend: %v", err)
	}
}

func TestWithNoTenantServiceCATheAPISaysSo(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Signer = nil
	ready(t, svc, "eds")
	_, _, err := svc.PutCertificate(context.Background(), "eds", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")})
	if !isInvalid(err) || !strings.Contains(err.Error(), "issues no certificates") {
		t.Fatalf("err = %v", err)
	}
}

func TestATenantThatDoesNotExistGetsNoCertificate(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	_, _, err := svc.PutCertificate(context.Background(), "ghost", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")})
	if !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if len(b.Signer.Calls) != 0 {
		t.Fatal("the signer was reached for a tenant that does not exist")
	}
}

// The same label in two tenants is two names, in two zones, and neither
// tenant's certificate is the other's.
func TestTwoTenantsWithTheSameLabelHoldDifferentNames(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ready(t, svc, "tdemo")
	ctx := context.Background()

	a, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := svc.PutCertificate(ctx, "tdemo", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")})
	if err != nil {
		t.Fatal(err)
	}
	if a.Names[0] != "console.eds.deevnet.net" || b.Names[0] != "console.tdemo.deevnet.net" {
		t.Fatalf("names: %v and %v", a.Names, b.Names)
	}
	if got, _ := svc.ListCertificates(ctx, "eds"); len(got) != 1 || got[0].Tenant != "eds" {
		t.Fatalf("eds holds %+v", got)
	}
}

func TestATenantHoldsOnlySoManyCertificates(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	key := tenanttest.NewKey()

	var err error
	for i := 0; i < 80 && err == nil; i++ {
		_, _, err = svc.PutCertificate(ctx, "eds", fmt.Sprintf("n%d", i),
			tenant.CertificateRequest{CSR: tenanttest.RequestFor(key, "x")})
	}
	if !isInvalid(err) {
		t.Fatalf("eighty certificates were issued: %v", err)
	}
	held, _ := svc.ListCertificates(ctx, "eds")
	if len(held) != 64 {
		t.Fatalf("the tenant holds %d", len(held))
	}
	// A name it already holds can still be reissued at the limit.
	if _, issued, err := svc.PutCertificate(ctx, "eds", "n0", tenant.CertificateRequest{CSR: tenanttest.Request("x")}); err != nil || !issued {
		t.Fatalf("reissuing at the limit: issued=%v err=%v", issued, err)
	}
}

func TestDeletingForgetsACertificateAndSaysWhenThereIsNone(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteCertificate(ctx, "eds", "console"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetCertificate(ctx, "eds", "console"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("still there: %v", err)
	}
	if err := svc.DeleteCertificate(ctx, "eds", "console"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("deleting what is not there: %v", err)
	}
}

// Removing a tenant takes its certificates' rows with it.
func TestRemovingATenantRemovesItsCertificates(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	ctx := context.Background()
	if _, _, err := svc.PutCertificate(ctx, "eds", "console", tenant.CertificateRequest{CSR: tenanttest.Request("x")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	ready(t, svc, "eds")
	if held, _ := svc.ListCertificates(ctx, "eds"); len(held) != 0 {
		t.Fatalf("a tenant made again holds its predecessor's certificates: %+v", held)
	}
}

// A service is named for its whole life, and the sites it runs at, or is headed
// for, are extra names beside it (ADR-0040 §1-§3).
func TestSitesAreExtraNames(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Site.CertificateSites = []string{"mobile", "home"}
	ready(t, svc, "eds")

	c, _, err := svc.PutCertificate(context.Background(), "eds", "console", tenant.CertificateRequest{
		CSR: tenanttest.Request("x"), Names: []string{"mqtt"}, Sites: []string{"home", "mobile"}})
	if err != nil {
		t.Fatal(err)
	}
	want := "console.eds.deevnet.net,mqtt.eds.deevnet.net," +
		"console.eds.home.deevnet.net,mqtt.eds.home.deevnet.net," +
		"console.eds.mobile.deevnet.net,mqtt.eds.mobile.deevnet.net"
	if strings.Join(c.Names, ",") != want {
		t.Fatalf("names = %v", c.Names)
	}

	for _, sites := range [][]string{{"elsewhere"}, {"home", "home"}} {
		if _, _, err := svc.PutCertificate(context.Background(), "eds", "other", tenant.CertificateRequest{
			CSR: tenanttest.Request("x"), Sites: sites}); !isInvalid(err) {
			t.Errorf("sites %v: %v, want refused", sites, err)
		}
	}
	// A site the API does not issue for is refused even when it is real.
	svc.Site.CertificateSites = nil
	if _, _, err := svc.PutCertificate(context.Background(), "eds", "other", tenant.CertificateRequest{
		CSR: tenanttest.Request("x"), Sites: []string{"home"}}); !isInvalid(err) {
		t.Errorf("home on an API that issues for mobile alone: %v, want refused", err)
	}
}

// device.<tenant>.<root> holds a tenant's device names (ADR-0039 §4).
func TestTheDeviceLabelIsReserved(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	ready(t, svc, "eds")
	for _, req := range []struct {
		name  string
		names []string
	}{{"device", nil}, {"console", []string{"device"}}} {
		if _, _, err := svc.PutCertificate(context.Background(), "eds", req.name, tenant.CertificateRequest{
			CSR: tenanttest.Request("x"), Names: req.names}); !isInvalid(err) {
			t.Errorf("%s %v: %v, want refused", req.name, req.names, err)
		}
	}
}

// A tenant named for a site, a global alias or the bus would hold its names
// (ADR-0040 §4).
func TestReservedTenantNamesAreRefused(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	for _, name := range []string{"home", "mobile", "mgmt", "dvnt", "dvntm", "device", "mqtt", "artifacts"} {
		if _, err := svc.Create(context.Background(), tenant.CreateRequest{Name: name}); !isInvalid(err) {
			t.Errorf("create %q: %v, want refused", name, err)
		}
		if _, err := svc.Admit(context.Background(), name, ""); !isInvalid(err) {
			t.Errorf("admit %q: %v, want refused", name, err)
		}
	}
}
