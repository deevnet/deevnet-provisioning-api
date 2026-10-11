package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

func aCertificate(serial, key string, notAfter time.Time) tenant.Certificate {
	return tenant.Certificate{
		Tenant: "eds", Name: "console",
		Names:          []string{"console.eds.mobile.deevnet.net", "www.eds.mobile.deevnet.net"},
		KeyFingerprint: key, Serial: serial,
		NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter,
		PEM:   "-----BEGIN CERTIFICATE-----\nleaf " + serial + "\n-----END CERTIFICATE-----\n",
		Chain: "-----BEGIN CERTIFICATE-----\nissuing\n-----END CERTIFICATE-----\n",
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	notAfter := time.Date(2027, 10, 11, 12, 0, 0, 0, time.UTC)

	put, err := p.PutCertificate(ctx, aCertificate("0a:0b", "k1", notAfter))
	if err != nil {
		t.Fatal(err)
	}
	if put.CreatedAt.IsZero() || put.UpdatedAt.IsZero() {
		t.Error("timestamps not populated")
	}
	got, err := p.GetCertificate(ctx, "eds", "console")
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != "0a:0b" || got.KeyFingerprint != "k1" || len(got.Names) != 2 ||
		got.Names[0] != "console.eds.mobile.deevnet.net" || got.PEM != put.PEM || got.Chain != put.Chain {
		t.Errorf("get returned %+v", got)
	}
	// An instant, in UTC, whatever zone the database session is in.
	if !got.NotAfter.Equal(notAfter) || got.NotAfter.Location() != time.UTC {
		t.Errorf("not_after = %v", got.NotAfter)
	}
}

// Reissuing replaces the row for a name: the registry holds the certificate
// current for it, and when it was first issued.
func TestReissuingReplacesTheCertificateForAName(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")

	first, err := p.PutCertificate(ctx, aCertificate("01", "k1", time.Now().Add(300*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.PutCertificate(ctx, aCertificate("02", "k2", time.Now().Add(365*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at moved: %v then %v", first.CreatedAt, second.CreatedAt)
	}
	list, err := p.ListCertificates(ctx, "eds")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Serial != "02" || list[0].KeyFingerprint != "k2" {
		t.Fatalf("list = %+v", list)
	}
}

func TestCertificatesBelongToATenantAndGoWithIt(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	seedTenantFor(t, p, "eds")
	seedTenantFor(t, p, "tdemo")

	if _, err := p.PutCertificate(ctx, aCertificate("01", "k1", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	// A tenant that is not there holds nothing.
	ghost := aCertificate("03", "k3", time.Now().Add(time.Hour))
	ghost.Tenant = "ghost"
	if _, err := p.PutCertificate(ctx, ghost); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("a certificate for a tenant that does not exist: %v", err)
	}
	// The same label under another tenant is another row.
	if _, err := p.GetCertificate(ctx, "tdemo", "console"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("tdemo reads eds's certificate: %v", err)
	}
	if list, _ := p.ListCertificates(ctx, "tdemo"); len(list) != 0 {
		t.Errorf("tdemo lists %+v", list)
	}

	// Deleting twice converges; deleting the tenant takes the rest.
	if err := p.DeleteCertificate(ctx, "eds", "console"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteCertificate(ctx, "eds", "console"); err != nil {
		t.Errorf("a repeated delete: %v", err)
	}
	if _, err := p.PutCertificate(ctx, aCertificate("04", "k4", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := p.Delete(ctx, "eds"); err != nil {
		t.Fatal(err)
	}
	seedTenantFor(t, p, "eds")
	if list, _ := p.ListCertificates(ctx, "eds"); len(list) != 0 {
		t.Errorf("a tenant made again holds %+v", list)
	}
}
