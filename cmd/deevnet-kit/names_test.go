package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"slices"
	"testing"
)

func serverCert(t *testing.T, k *kit) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	caPEM, _ := os.ReadFile(k.caFile())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	b, _ := os.ReadFile(k.serverFile())
	blk, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pool
}

func TestBootConfigNames(t *testing.T) {
	bc, err := readBootConfig(bootConfig(t, "names=mqtt.home.example.net, Console.Eds.Home.Example.NET. 192.168.2.40,mqtt.home.example.net\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mqtt.home.example.net", "console.eds.home.example.net", "192.168.2.40"}
	if !slices.Equal(bc.Names, want) {
		t.Errorf("names = %q, want %q", bc.Names, want)
	}
	for _, bad := range []string{"names=*.home.example.net\n", "names=has_underscore.example.net\n", "names=-bad.example.net\n", "names=a..b\n"} {
		if _, err := readBootConfig(bootConfig(t, bad)); err == nil {
			t.Errorf("%q: accepted, want an error", bad)
		}
	}
	if bc, err := readBootConfig(bootConfig(t, "names=\n")); err != nil || len(bc.Names) != 0 {
		t.Errorf("an empty names= should be no names, got %q %v", bc.Names, err)
	}
}

// A name or address given on the boot partition is on the certificate the
// first boot issues, before the Pi has that address or the site's DNS points
// at it.
func TestFirstBootCertificateCarriesTheExtraNames(t *testing.T) {
	k, _ := initKit(t, "names=mqtt.home.example.net,192.168.2.40\n")
	cert, pool := serverCert(t, k)
	for _, name := range []string{"mqtt.home.example.net", "192.168.2.40", "localhost"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "other.home.example.net", Roots: pool}); err == nil {
		t.Error("the certificate verified for a name it was not given")
	}
	if names, _ := k.readNames(); !slices.Equal(names, []string{"mqtt.home.example.net", "192.168.2.40"}) {
		t.Errorf("names file holds %q", names)
	}
}

func TestNamesCommandAndRegen(t *testing.T) {
	k, _ := initKit(t, "")
	if names, err := k.readNames(); err != nil || names != nil {
		t.Fatalf("a card with no names= has names %q (%v)", names, err)
	}
	steps := []struct {
		args []string
		want []string
	}{
		{[]string{"set", "a.example.net", "10.0.0.9"}, []string{"a.example.net", "10.0.0.9"}},
		{[]string{"add", "b.example.net,a.example.net"}, []string{"a.example.net", "10.0.0.9", "b.example.net"}},
		{[]string{"rm", "10.0.0.9"}, []string{"a.example.net", "b.example.net"}},
	}
	for _, s := range steps {
		if err := k.cmdNames(s.args); err != nil {
			t.Fatalf("names %v: %v", s.args, err)
		}
		if got, _ := k.readNames(); !slices.Equal(got, s.want) {
			t.Errorf("after names %v: %q, want %q", s.args, got, s.want)
		}
	}
	if err := k.cmdNames([]string{"add", "*.example.net"}); err == nil {
		t.Error("a wildcard was added")
	}
	if err := k.cmdNames([]string{"frob"}); err == nil {
		t.Error("an unknown subcommand was accepted")
	}

	// Nothing changes until regen-certs; then both names are on it.
	cert, pool := serverCert(t, k)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "b.example.net", Roots: pool}); err == nil {
		t.Error("the names were applied before regen-certs")
	}
	if err := k.cmdRegenCerts(); err != nil {
		t.Fatal(err)
	}
	cert, pool = serverCert(t, k)
	for _, name := range []string{"a.example.net", "b.example.net"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil {
			t.Errorf("after regen, %s: %v", name, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "10.0.0.9", Roots: pool}); err == nil {
		t.Error("a removed address is still on the certificate")
	}
}
