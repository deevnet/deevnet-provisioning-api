package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// A PKI of the owner's own (ADR-0041 §3, §4): the starter kit for leaving
// Deevnet. Two tiers: the owner's root on an encrypted USB stick, and one
// issuing CA on this Pi, which signs the Pi's server certificate and its
// devices'. The ceremony tools do the signing (deevnet-pki-owner.sh, from
// deevnet.mgmt's scripts/pki, on the image); this file runs them and installs
// what they make.
//
// Leaving is a trust transition, in order, with the service up throughout:
//
//  1. pki init makes the root and the issuing CA. Nothing served changes;
//     export now hands out a bundle of the root trusted today and the
//     owner's, for every device and computer.
//  2. pki switch, once they all hold it: the Pi's certificate is reissued by
//     the owner's CA, and everything here trusts the owner's root.
//  3. The old root is removed from devices last: export hands out the
//     owner's root alone.
//
// A card that never left its own CA takes the same path; a card with nothing
// pointed at it yet can run pki switch straight after pki init.

const (
	pkiOwner = "owner"

	ownerRootExportName = "owner-root-ca.pem"
	// trustBundleName is what export hands out between pki init and pki
	// switch: the root trusted now and the owner's, so a device given it
	// keeps working across the switch.
	trustBundleName = "trust-bundle.pem"

	ownerIssuingKey  = "owner-issuing-ca.key"
	ownerIssuingCert = "owner-issuing-ca.pem"
	ownerRootCert    = "owner-root-ca.pem"

	defaultOwnerTool = "/usr/local/sbin/deevnet-pki-owner.sh"
)

func (st state) owner() bool { return st.PKI == pkiOwner }

func (k *kit) ownerDir() string         { return filepath.Join(k.etc(), "owner-ca") }
func (k *kit) previousRootFile() string { return filepath.Join(k.tlsDir(), "previous-root.pem") }

func (k *kit) ownerTool() string {
	if k.tool != "" {
		return k.tool
	}
	return defaultOwnerTool
}

// ownerReady is whether an issuing CA of the owner's is on this Pi.
func (k *kit) ownerReady() bool {
	for _, f := range []string{ownerIssuingKey, ownerIssuingCert, ownerRootCert} {
		if _, err := os.Stat(filepath.Join(k.ownerDir(), f)); err != nil {
			return false
		}
	}
	return true
}

// runTool runs the ceremony tool on the owner's terminal: it asks for the
// stick and the root key's passphrase itself. A variable, so tests can set
// its environment.
var runTool = func(argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", filepath.Base(argv[0]), argv[1], err)
	}
	return nil
}

func (k *kit) cmdPKI(w io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("pki init | issuing | switch | enroll DEVICE")
	}
	switch args[0] {
	case "init", "issuing":
		return k.pkiCA(w, args[0], args[1:])
	case "switch":
		if len(args) != 1 {
			return errors.New("pki switch takes no arguments")
		}
		return k.pkiSwitch(w)
	case "enroll":
		return k.pkiEnroll(w, args[1:])
	}
	return fmt.Errorf("pki %s: want init, issuing, switch or enroll", args[0])
}

// pkiCA makes the owner's issuing CA: under a new root on the stick (init),
// or under the root already on it (issuing: a new card, or one that was lost).
func (k *kit) pkiCA(w io.Writer, mode string, args []string) error {
	fs := flag.NewFlagSet("pki "+mode, flag.ContinueOnError)
	org := fs.String("org", "", "the organization name the CAs carry")
	keys := fs.String("keys", "", "an encrypted stick already open, in place of inserting one")
	var domains multiFlag
	fs.Var(&domains, "domain", "a domain of the owner's the Pi may be named in (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("pki %s takes only flags", mode)
	}
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if *org == "" && mode == "issuing" {
		*org = st.OwnerOrg
	}
	if *org == "" {
		return fmt.Errorf("pki %s --org: the organization name your CAs carry, such as \"Mabell Home\"", mode)
	}
	if len(domains) == 0 && mode == "issuing" {
		domains = st.OwnerDomains
	}
	if k.ownerReady() {
		return fmt.Errorf("an issuing CA of yours is already on this Pi (%s); to replace it, move that directory aside first", k.ownerDir())
	}
	argv := []string{k.ownerTool(), mode, "--org", *org, "--out", k.ownerDir()}
	for _, d := range domains {
		argv = append(argv, "--domain", d)
	}
	if *keys != "" {
		argv = append(argv, "--keys", *keys)
	}
	if err := runTool(argv...); err != nil {
		return err
	}
	issuing, err := k.checkOwnerCA()
	if err != nil {
		return err
	}
	st.OwnerOrg, st.OwnerDomains = *org, domains
	if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nYour issuing CA, %s, is on this Pi; your root stays on the stick.\n", issuing.Subject.CommonName)
	if st.owner() {
		fmt.Fprintln(w, "This Pi already serves on your root: run sudo deevnet-kit pki switch to reissue its certificate from the new issuing CA.")
		return nil
	}
	fmt.Fprintln(w, "Nothing this Pi serves has changed yet. Next:")
	fmt.Fprintf(w, "  1. sudo deevnet-kit export DIR writes %s: the root trusted now and yours.\n", trustBundleName)
	fmt.Fprintln(w, "     Give it to every device and computer that talks to this Pi, in place of the CA file they have.")
	fmt.Fprintln(w, "  2. Then: sudo deevnet-kit pki switch. Devices given the bundle keep working across it.")
	fmt.Fprintf(w, "  3. Once every device holds it, export again and give them %s alone.\n", ownerRootExportName)
	return nil
}

// checkOwnerCA checks what the tool made before anything uses it: an issuing
// CA that chains to the root beside it, may sign only leaves, and is
// constrained to the owner's names.
func (k *kit) checkOwnerCA() (*x509.Certificate, error) {
	read := func(name string) ([]*x509.Certificate, error) {
		b, err := os.ReadFile(filepath.Join(k.ownerDir(), name))
		if err != nil {
			return nil, err
		}
		return parseCerts(b)
	}
	roots, err := read(ownerRootCert)
	if err != nil || len(roots) != 1 {
		return nil, fmt.Errorf("the tool left no root certificate in %s", k.ownerDir())
	}
	issuings, err := read(ownerIssuingCert)
	if err != nil || len(issuings) != 1 {
		return nil, fmt.Errorf("the tool left no issuing CA certificate in %s", k.ownerDir())
	}
	root, issuing := roots[0], issuings[0]
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := issuing.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("the issuing CA does not chain to the root beside it: %w", err)
	}
	if !issuing.IsCA || !issuing.MaxPathLenZero || len(issuing.PermittedDNSDomains) == 0 {
		return nil, errors.New("the issuing CA is not a constrained CA for leaves only")
	}
	if _, err := os.Stat(filepath.Join(k.ownerDir(), "owner-root-ca.key")); err == nil {
		return nil, fmt.Errorf("%s holds the root key: it belongs only on the stick; remove it", k.ownerDir())
	}
	return issuing, nil
}

// pkiSwitch is step 2: the Pi's certificate from the owner's CA, and the
// owner's root trusted by everything here. The root it trusted before is kept
// beside it, so going back is a copy.
func (k *kit) pkiSwitch(w io.Writer) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if !k.ownerReady() {
		return errors.New("no issuing CA of yours is on this Pi: run deevnet-kit pki init first")
	}
	if st.owner() {
		return errors.New("this Pi already serves on your root; to reissue its certificate: sudo deevnet-kit regen-certs")
	}
	if _, err := k.checkOwnerCA(); err != nil {
		return err
	}
	if err := k.issueOwnerServerCert(w, st); err != nil {
		return err
	}
	if prev, err := os.ReadFile(k.caFile()); err == nil {
		if err := writeFile(k.previousRootFile(), prev, 0o644); err != nil {
			return err
		}
	}
	root, err := os.ReadFile(filepath.Join(k.ownerDir(), ownerRootCert))
	if err != nil {
		return err
	}
	if err := writeFile(k.caFile(), root, 0o644); err != nil {
		return err
	}
	was := st.PKI
	st.PKI = pkiOwner
	if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
		return err
	}
	// A Deevnet Pi's services dialled its Deevnet names, mapped to loopback;
	// on the owner's root they dial localhost, which the certificate names.
	if err := k.writeHosts(st); err != nil {
		return err
	}
	if err := k.writeBridgeEnv(st); err != nil {
		return err
	}
	fmt.Fprintf(w, "switched: this Pi serves a certificate from your issuing CA, and trusts your root (%s)\n", st.OwnerOrg)
	if was == pkiDeevnet {
		fmt.Fprintln(w, "it is no longer a Deevnet Pi: its Deevnet names are not in the new certificate")
	}
	fmt.Fprintf(w, "once every device holds your root: sudo deevnet-kit export DIR, and give them %s alone\n", ownerRootExportName)
	return k.restartForCert()
}

// issueOwnerServerCert has the tool issue the Pi's server certificate, then
// installs it: for the names the Pi answers to on its own network, which the
// owner's CA may sign for. An extra name it may not is left out, and said.
func (k *kit) issueOwnerServerCert(w io.Writer, st state) error {
	h, err := os.Hostname()
	if err != nil {
		return err
	}
	extra, err := k.readNames()
	if err != nil {
		return err
	}
	names, dropped := ownerServerNames(h, localAddrs(), extra, st.OwnerDomains)
	for _, n := range dropped {
		fmt.Fprintf(w, "left out %s: your CA signs only .local names, localhost, private addresses and %s\n",
			n, orNone(st.OwnerDomains))
	}
	tmp, err := os.MkdirTemp(k.tlsDir(), "owner-leaf.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	argv := []string{k.ownerTool(), "leaf", "server", "--ca", k.ownerDir(), "--out", tmp}
	for _, n := range names {
		argv = append(argv, "--name", n)
	}
	if err := runTool(argv...); err != nil {
		return err
	}
	cn := names[0]
	keyPEM, err := os.ReadFile(filepath.Join(tmp, cn+".key"))
	if err != nil {
		return err
	}
	fullchain, err := os.ReadFile(filepath.Join(tmp, cn+"-fullchain.pem"))
	if err != nil {
		return err
	}
	certs, err := parseCerts(fullchain)
	if err != nil {
		return err
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return fmt.Errorf("the tool's key: %w", err)
	}
	if !key.PublicKey.Equal(certs[0].PublicKey) {
		return errors.New("the tool's certificate is not for its key")
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
	fmt.Fprintf(w, "server certificate for %s, valid to %s\n", strings.Join(names, ", "), certs[0].NotAfter.Format("2006-01-02"))
	return nil
}

// ownerServerNames is what the owner's CA is asked to name: <host>.local,
// localhost for the services here, loopback, the Pi's private addresses, and
// the extra names it may sign for. The bare host name is not among them: no
// name constraint covers a single label, so the CA would refuse it.
func ownerServerNames(h string, addrs []net.IP, extra, domains []string) (names, dropped []string) {
	h = strings.TrimSuffix(h, ".local")
	names = []string{h + ".local", "localhost", "127.0.0.1", "::1"}
	add := func(n string) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, ip := range addrs {
		if ip.IsPrivate() {
			add(ip.String())
		}
	}
	for _, n := range extra {
		if ownerMaySign(n, domains) {
			add(n)
		} else {
			dropped = append(dropped, n)
		}
	}
	return names, dropped
}

// ownerMaySign mirrors the issuing CA's name constraints
// (deevnet-pki-owner.cnf), so a name it would refuse is left out with a
// reason rather than failing the whole certificate.
func ownerMaySign(n string, domains []string) bool {
	if ip := net.ParseIP(n); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback()
	}
	if n == "localhost" || strings.HasSuffix(n, ".local") {
		return true
	}
	for _, d := range domains {
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
}

func orNone(domains []string) string {
	if len(domains) == 0 {
		return "no domain of yours (pki init --domain)"
	}
	return strings.Join(domains, ", ")
}

// pkiEnroll issues a device's certificate from the owner's CA: a key of its
// own made here, or a request the device made.
func (k *kit) pkiEnroll(w io.Writer, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("pki enroll DEVICE --out DIR [--csr FILE]")
	}
	device := args[0]
	fs := flag.NewFlagSet("pki enroll", flag.ContinueOnError)
	out := fs.String("out", "", "where the device's files go")
	csr := fs.String("csr", "", "the device's own signing request, in place of a key made here")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("pki enroll DEVICE --out DIR [--csr FILE]")
	}
	if !k.ownerReady() {
		return errors.New("no issuing CA of yours is on this Pi: run deevnet-kit pki init first")
	}
	argv := []string{k.ownerTool(), "leaf", "device", "--ca", k.ownerDir(), "--out", *out, "--name", device}
	if *csr != "" {
		argv = append(argv, "--csr", *csr)
	}
	if err := runTool(argv...); err != nil {
		return err
	}
	root := filepath.Join(*out, ownerRootExportName)
	b, err := os.ReadFile(filepath.Join(k.ownerDir(), ownerRootCert))
	if err != nil {
		return err
	}
	if err := writeFile(root, b, 0o644); err != nil {
		return err
	}
	files := []string{*out, root, filepath.Join(*out, device+".pem"), filepath.Join(*out, device+"-fullchain.pem")}
	if *csr == "" {
		files = append(files, filepath.Join(*out, device+".key"))
	}
	if err := chownToSudoUser(files...); err != nil {
		return err
	}
	fmt.Fprintf(w, "the device needs %s.pem (or -fullchain.pem)%s, and %s to trust this Pi\n",
		device, map[bool]string{true: "", false: " and " + device + ".key"}[*csr != ""], ownerRootExportName)
	return nil
}

// chownToSudoUser hands files to the user who ran sudo, so files written into
// their home are theirs.
func chownToSudoUser(paths ...string) error {
	uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uid == "" || gid == "" {
		return nil
	}
	u, _ := strconv.Atoi(uid)
	g, _ := strconv.Atoi(gid)
	for _, p := range paths {
		if err := os.Chown(p, u, g); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// exportCA is what export writes for apps and devices to trust, and its name:
// the root trusted now, or, between pki init and pki switch, a bundle of that
// and the owner's.
func (k *kit) exportCA(st state) (string, []byte, error) {
	ca, err := os.ReadFile(k.caFile())
	if err != nil {
		return "", nil, err
	}
	if st.owner() || !k.ownerReady() {
		return st.caExportName(), ca, nil
	}
	owner, err := os.ReadFile(filepath.Join(k.ownerDir(), ownerRootCert))
	if err != nil {
		return "", nil, err
	}
	return trustBundleName, append(append(bytes.TrimSpace(ca), '\n'), owner...), nil
}

// ownerCertWarning: the addresses a device could dial that the certificate
// does not name. Only private ones count: the owner's CA cannot name another.
func (k *kit) ownerCertWarning() (string, error) {
	missing, err := k.uncoveredAddrs()
	if err != nil {
		return "", err
	}
	var private []net.IP
	for _, ip := range missing {
		if ip.IsPrivate() {
			private = append(private, ip)
		}
	}
	if len(private) == 0 {
		return "", nil
	}
	return fmt.Sprintf("the certificate does not name %v; a device dialling it will fail: sudo deevnet-kit regen-certs", private), nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
