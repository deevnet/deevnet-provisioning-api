package tenant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Server certificates for a tenant's own services (ADR-0037, CHG-0047).
//
// A tenant makes a key and sends a signing request for a label in its own
// zone. The site's Tenant Service CA signs it, in the secret store, and the
// certificate comes back with its chain. The key never comes here.
//
// Three rules carry the weight, and each is here rather than left to the
// signer:
//
//   - The tenant sends labels, never names. Every name in a certificate is
//     built here: <label>.<tenant>.<root>, the service's name wherever it
//     runs, then <label>.<tenant>.<site>.<root> for each site the tenant
//     asks for among those this API issues for (ADR-0040 §1-§3). A tenant
//     cannot spell a name outside its own: it never spells a zone.
//   - The request is read for its public key and nothing else. Its subject,
//     its names and its extensions are not used (Certificates standard 4.6).
//   - What the signer returns is checked before anyone is handed it. A
//     certificate that says more than was asked is refused here, not trusted
//     because of where it came from.
//
// The signer's own role ignores the request's names and permits only names at
// least two labels below the root. That no longer tells a tenant's name from a
// site's (console.eds.deevnet.net and grafana.home.deevnet.net are both two
// labels down), so the reserved tenant names (Reserved) are what keep a
// tenant off a site's names, here alone until each tenant has a role of its
// own.

const (
	// CertificateRenewBefore is how long before expiry a certificate is
	// reissued when asked for again (Certificates standard 4.7).
	CertificateRenewBefore = 60 * 24 * time.Hour

	// maxCertificateNames bounds the names in one certificate: its own and
	// those beside it.
	maxCertificateNames = 8
	// maxCertificatesPerTenant bounds how many a tenant holds. Each is a name
	// it serves; the bound is there so that a loop in someone's configuration
	// is a refused request, not a full table.
	maxCertificatesPerTenant = 64
	// maxCertificateLifetime is the longest a leaf may be valid and still be
	// accepted from the signer: a year, and the signer's allowance for clocks.
	maxCertificateLifetime = 366*24*time.Hour + time.Hour
)

// CertificateRequest is a tenant asking for a certificate.
type CertificateRequest struct {
	// CSR is a PEM PKCS#10 request. Only its public key is used, and its
	// signature, which shows the sender holds the private key.
	CSR string
	// Names are further labels for the certificate to be valid for, beside
	// its own.
	Names []string
	// Sites are the sites to name it at as well, each one the API issues for.
	// Empty means this site alone.
	Sites []string
}

// Certificate is a server certificate the API issued, as the registry holds
// it. Everything in it is public.
type Certificate struct {
	Tenant string
	// Name is the label the certificate is for, and how it is addressed.
	Name string
	// Names are every DNS name in it, fully qualified, its own first.
	Names []string
	// KeyFingerprint is the SHA-256 of the public key it certifies, in hex.
	// It is how a repeated request is told from one with a new key.
	KeyFingerprint string
	Serial         string
	NotBefore      time.Time
	NotAfter       time.Time
	// PEM is the leaf. Chain is the issuing CA and the Site CA, in the order
	// a server presents them after the leaf, and never the root.
	PEM       string
	Chain     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RenewAfter is when asking again yields a new certificate.
func (c Certificate) RenewAfter() time.Time { return c.NotAfter.Add(-CertificateRenewBefore) }

// SignedCertificate is what a signer returns.
type SignedCertificate struct {
	// Certificate is the leaf, PEM.
	Certificate string
	// Chain is the CAs above it, PEM, issuing CA first. The root is not
	// wanted in it and is dropped if it is there.
	Chain []string
}

// CertificateSigner has the site's Tenant Service CA sign a request.
//
// It is the secret store. The names are the ones to certify, fully qualified,
// the first of them the common name; the signer takes nothing else from the
// request but its key.
//
// Nil is legal: a site with no Tenant Service CA is a legitimate site, and the
// certificate routes then refuse with a reason.
type CertificateSigner interface {
	SignServer(ctx context.Context, csrPEM string, names []string) (SignedCertificate, error)
}

// PutCertificate issues a certificate for a label in the tenant's zone, or
// returns the one already issued.
//
// Asking again with the same key and the same names returns the same
// certificate while more than CertificateRenewBefore remains. A new key, a
// changed name, or less time than that, issues another. The second result
// reports whether this call issued one.
func (s *Service) PutCertificate(ctx context.Context, tenantName, name string, req CertificateRequest) (Certificate, bool, error) {
	if s.Signer == nil {
		return Certificate{}, false, invalid("this API issues no certificates")
	}
	rec, err := s.Store.Get(ctx, tenantName)
	if err != nil {
		return Certificate{}, false, err
	}
	if rec.Status != StatusReady {
		return Certificate{}, false, invalid("tenant %q is %s", tenantName, rec.Status)
	}

	labels, err := certificateLabels(name, req.Names)
	if err != nil {
		return Certificate{}, false, err
	}
	sites, err := s.certificateSites(req.Sites)
	if err != nil {
		return Certificate{}, false, err
	}
	names := certificateNames(s.Site, tenantName, labels, sites)

	csr, fingerprint, err := parseCertificateRequest(req.CSR)
	if err != nil {
		return Certificate{}, false, err
	}

	existing, err := s.Store.GetCertificate(ctx, tenantName, name)
	switch {
	case errors.Is(err, ErrNotFound):
		held, err := s.Store.ListCertificates(ctx, tenantName)
		if err != nil {
			return Certificate{}, false, err
		}
		if len(held) >= maxCertificatesPerTenant {
			return Certificate{}, false, invalid("the tenant holds %d certificates, which is as many as one tenant may", len(held))
		}
	case err != nil:
		return Certificate{}, false, err
	case existing.KeyFingerprint == fingerprint && slices.Equal(existing.Names, names) &&
		s.now().Before(existing.RenewAfter()):
		// The same question, with time to spare: the same answer.
		return existing, false, nil
	}

	signed, err := s.Signer.SignServer(ctx, csr, names)
	if err != nil {
		s.logger().Error("signing a certificate", "tenant", tenantName, "certificate", name, "err", err)
		return Certificate{}, false, &StepError{Step: StepCertificate, Err: err}
	}
	cert, err := checkSigned(signed, names, fingerprint, s.now())
	if err != nil {
		// The signer answered, and what it answered is not what was asked
		// for. Nobody is given it.
		s.logger().Error("the signer returned a certificate that was not asked for",
			"tenant", tenantName, "certificate", name, "err", err)
		return Certificate{}, false, &StepError{Step: StepCertificate, Err: err}
	}
	cert.Tenant, cert.Name = tenantName, name

	cert, err = s.Store.PutCertificate(ctx, cert)
	if err != nil {
		return Certificate{}, false, err
	}
	s.audit(ctx, "certificate-issue", tenantName, map[string]any{
		"certificate": name, "names": names, "serial": cert.Serial,
		"key": fingerprint, "not_after": cert.NotAfter.UTC().Format(time.RFC3339),
	})
	return cert, true, nil
}

// GetCertificate returns one certificate.
func (s *Service) GetCertificate(ctx context.Context, tenantName, name string) (Certificate, error) {
	return s.Store.GetCertificate(ctx, tenantName, name)
}

// ListCertificates returns a tenant's certificates.
func (s *Service) ListCertificates(ctx context.Context, tenantName string) ([]Certificate, error) {
	return s.Store.ListCertificates(ctx, tenantName)
}

// DeleteCertificate forgets a certificate. It does not revoke it: nothing on
// the site can (ADR-0037). Whoever holds its key can serve with it until it
// expires, and a tenant that has lost a key should know that this does not
// help.
func (s *Service) DeleteCertificate(ctx context.Context, tenantName, name string) error {
	c, err := s.Store.GetCertificate(ctx, tenantName, name)
	if err != nil {
		return err
	}
	s.audit(ctx, "certificate-delete", tenantName, map[string]any{
		"certificate": name, "serial": c.Serial,
		"still_valid_until": c.NotAfter.UTC().Format(time.RFC3339),
	})
	return s.Store.DeleteCertificate(ctx, tenantName, name)
}

// certificateSites checks the sites a certificate is asked to name.
func (s *Service) certificateSites(asked []string) ([]string, error) {
	allowed := s.Site.certificateSites()
	if len(asked) == 0 {
		return []string{s.Site.Name}, nil
	}
	var out []string
	for _, site := range asked {
		if !slices.Contains(allowed, site) {
			return nil, invalid("site %q is not one this API issues for: %s", site, strings.Join(allowed, ", "))
		}
		if slices.Contains(out, site) {
			return nil, invalid("site %q is given twice", site)
		}
		out = append(out, site)
	}
	return out, nil
}

// certificateNames are every name a certificate holds: each label's
// site-less name first, its own first of all and so its common name, then
// each label at each site (ADR-0040 §3).
func certificateNames(site Site, tenantName string, labels, sites []string) []string {
	names := make([]string, 0, len(labels)*(1+len(sites)))
	for _, label := range labels {
		names = append(names, label+"."+site.ServiceZone(tenantName))
	}
	for _, at := range sites {
		for _, label := range labels {
			names = append(names, label+"."+site.SiteZone(tenantName, at))
		}
	}
	return names
}

// certificateLabels checks the certificate's own label and those beside it,
// and returns them, its own first, the rest in the order given.
func certificateLabels(name string, more []string) ([]string, error) {
	const rule = "must be 1-20 lowercase alphanumerics or dashes, starting with a letter"
	if !ValidWorkloadName(name) {
		return nil, invalid("certificate name %s", rule)
	}
	// device.<tenant>.<root> holds the tenant's device names (ADR-0039 §4).
	if name == "device" {
		return nil, invalid("certificate name %q is reserved for the tenant's devices", name)
	}
	labels := []string{name}
	for _, label := range more {
		// A label, so no dot: a tenant names things in its zone and never the
		// zone, and "*" is not a label at all.
		if !ValidWorkloadName(label) {
			return nil, invalid("name %q %s; a name is one label in the tenant's zone, with no dot and no wildcard", label, rule)
		}
		if label == "device" {
			return nil, invalid("name %q is reserved for the tenant's devices", label)
		}
		if slices.Contains(labels, label) {
			return nil, invalid("name %q is given twice", label)
		}
		labels = append(labels, label)
	}
	if len(labels) > maxCertificateNames {
		return nil, invalid("a certificate holds at most %d names, and %d were asked for", maxCertificateNames, len(labels))
	}
	return labels, nil
}

// parseCertificateRequest reads a signing request for the only two things it
// is trusted for: that its sender holds the key, and what the key is. It
// returns the request re-encoded, so that what goes to the signer is one
// request and nothing that travelled beside it, and the key's fingerprint.
func parseCertificateRequest(in string) (csrPEM, fingerprint string, err error) {
	block, rest := pem.Decode([]byte(in))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", "", invalid("csr must be one PEM certificate request")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", "", invalid("csr must be one PEM certificate request, with nothing after it")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", invalid("csr could not be read as a certificate request")
	}
	// Whoever sent it holds the private key. Without this a certificate could
	// be had for a key that is someone else's.
	if err := csr.CheckSignature(); err != nil {
		return "", "", invalid("csr is not signed by its own key")
	}
	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits < 2048 || bits > 8192 {
			return "", "", invalid("csr has an RSA key of %d bits; it must be 2048 to 8192", bits)
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return "", "", invalid("csr has an ECDSA key on %s; the only curve taken is P-256", key.Curve.Params().Name)
		}
	default:
		return "", "", invalid("csr must carry an RSA key of 2048 bits or more, or an ECDSA P-256 key")
	}
	clean := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	return string(clean), keyFingerprint(csr.RawSubjectPublicKeyInfo), nil
}

func keyFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// checkSigned holds what the signer returned to what was asked for, and turns
// it into a Certificate. An error here is the signer's fault, never the
// tenant's.
func checkSigned(signed SignedCertificate, names []string, fingerprint string, now time.Time) (Certificate, error) {
	block, rest := pem.Decode([]byte(signed.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return Certificate{}, errors.New("not one PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("unreadable certificate: %w", err)
	}

	switch {
	case keyFingerprint(leaf.RawSubjectPublicKeyInfo) != fingerprint:
		return Certificate{}, errors.New("it certifies a key that is not the request's")
	case !sameNames(leaf.DNSNames, names):
		return Certificate{}, fmt.Errorf("its names are %v, and %v were asked for", leaf.DNSNames, names)
	case leaf.Subject.CommonName != names[0]:
		return Certificate{}, fmt.Errorf("its common name is %q, not %q", leaf.Subject.CommonName, names[0])
	case len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0:
		return Certificate{}, errors.New("it carries a name that is not a DNS name")
	case leaf.IsCA:
		return Certificate{}, errors.New("it is a CA")
	case len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0:
		return Certificate{}, errors.New("its usage is not server authentication alone")
	case leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0:
		return Certificate{}, errors.New("it may sign certificates")
	case !leaf.NotAfter.After(now):
		return Certificate{}, errors.New("it has already expired")
	case leaf.NotAfter.Sub(leaf.NotBefore) > maxCertificateLifetime:
		return Certificate{}, fmt.Errorf("it is valid for %s, longer than a year", leaf.NotAfter.Sub(leaf.NotBefore))
	}

	chain, err := cleanChain(signed.Chain)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{
		Names:          names,
		KeyFingerprint: fingerprint,
		Serial:         serialString(leaf),
		NotBefore:      leaf.NotBefore.UTC(),
		NotAfter:       leaf.NotAfter.UTC(),
		PEM:            string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		Chain:          chain,
	}, nil
}

// sameNames reports whether two lists hold the same names. Order is not a
// difference: a signer may list a certificate's names as it likes.
func sameNames(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// cleanChain is the CAs a server presents after its leaf: every one the
// signer gave that is not a root. A client holds the root, and a root sent to
// it is a root it must ignore.
func cleanChain(in []string) (string, error) {
	var out bytes.Buffer
	for _, entry := range in {
		rest := []byte(entry)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return "", errors.New("the chain holds something that is not a certificate")
			}
			ca, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", fmt.Errorf("unreadable certificate in the chain: %w", err)
			}
			if !ca.IsCA {
				return "", errors.New("the chain holds a certificate that is not a CA")
			}
			if bytes.Equal(ca.RawSubject, ca.RawIssuer) {
				continue // self-issued: the root
			}
			_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		}
	}
	if out.Len() == 0 {
		return "", errors.New("no issuing CA came with it")
	}
	return out.String(), nil
}

// serialString is a serial as certificates are usually shown: hex pairs,
// colon separated.
func serialString(c *x509.Certificate) string {
	raw := hex.EncodeToString(c.SerialNumber.Bytes())
	var parts []string
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":")
}
