package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Extra names for the server certificate.
//
// The certificate names what the Pi answers to on its own: <hostname>.local,
// the bare hostname, localhost and the addresses it has when the certificate
// is issued. A Pi with a name in a site's DNS, or one about to move to a
// network where it will have another address, needs more: a device verifying
// mqtt.home.example.net, or an address the Pi does not have yet. Those are kept
// here, one a line, and every certificate issued afterwards carries them.
//
// The file is the owner's, plain and not secret, and is read each time a
// certificate is issued: first boot (from names= on the boot partition) and
// regen-certs. Editing it changes nothing until regen-certs.

func (k *kit) namesFile() string { return filepath.Join(k.etc(), "names") }

// readNames returns the extra names. No file is no extra names.
func (k *kit) readNames() ([]string, error) {
	f, err := os.Open(k.namesFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, err := checkName(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.namesFile(), err)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, sc.Err()
}

func (k *kit) writeNames(names []string) error {
	if err := os.MkdirAll(k.etc(), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Extra names and addresses for this Pi's server certificate, one a line.\n")
	b.WriteString("# Edit with `deevnet-kit names`; `deevnet-kit regen-certs` applies them.\n")
	for _, n := range names {
		b.WriteString(n + "\n")
	}
	return writeFile(k.namesFile(), []byte(b.String()), 0o644)
}

// checkName accepts an IP address or a DNS name, and returns it in the form
// the certificate will carry. A wildcard is refused: this certificate's key is
// on the card, and a wildcard would let the card answer for every name in a zone.
func checkName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	if name == "" || len(name) > 253 || strings.Contains(name, "*") {
		return "", fmt.Errorf("%q is not a host name or an address", s)
	}
	for _, label := range strings.Split(name, ".") {
		if !hostnameRE.MatchString(label) {
			return "", fmt.Errorf("%q is not a host name or an address", s)
		}
	}
	return name, nil
}

// parseNames reads a comma- or space-separated list, as names= on the boot
// partition gives it.
func parseNames(list string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		name, err := checkName(f)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// withNames adds the extra names to the defaults, addresses to the addresses
// and the rest to the DNS names, leaving out any already there.
func withNames(dns []string, ips []net.IP, extra []string) ([]string, []net.IP) {
	for _, n := range extra {
		if ip := net.ParseIP(n); ip != nil {
			if !slices.ContainsFunc(ips, ip.Equal) {
				ips = append(ips, ip)
			}
			continue
		}
		if !slices.Contains(dns, n) {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

// cmdNames: names [list] | names set N... | names add N... | names rm N...
func (k *kit) cmdNames(args []string) error {
	cur, err := k.readNames()
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "list" {
		for _, n := range cur {
			fmt.Println(n)
		}
		return nil
	}
	given, err := parseNames(strings.Join(args[1:], ","))
	if err != nil {
		return err
	}
	var next []string
	switch args[0] {
	case "set":
		next = given
	case "add":
		next = cur
		for _, n := range given {
			if !slices.Contains(next, n) {
				next = append(next, n)
			}
		}
	case "rm", "remove":
		for _, n := range cur {
			if !slices.Contains(given, n) {
				next = append(next, n)
			}
		}
	default:
		return fmt.Errorf("names %s: want list, set, add or rm", args[0])
	}
	if err := k.writeNames(next); err != nil {
		return err
	}
	fmt.Printf("%d extra names; run `sudo deevnet-kit regen-certs` to issue a certificate with them\n", len(next))
	return nil
}
