package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// The owner's host name and Wi-Fi, from deevnet-kit.txt, applied once at first
// boot. Imager offers no OS customization for a custom image, so without these
// every card is raspberrypi.local and joins no Wi-Fi.

// applyHostname makes the card <name>.local. Before the server certificate is
// issued, because the certificate names it.
func (k *kit) applyHostname(name string) error {
	if name == "" {
		return nil
	}
	if err := writeFile(k.p("/etc/hostname"), []byte(name+"\n"), 0o644); err != nil {
		return err
	}
	// Raspberry Pi OS resolves its own name through a 127.0.1.1 line; left
	// naming raspberrypi, sudo complains on every call.
	hosts, err := os.ReadFile(k.p("/etc/hosts"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	line := "127.0.1.1\t" + name
	if loopback.Match(hosts) {
		hosts = loopback.ReplaceAll(hosts, []byte(line))
	} else {
		hosts = append(hosts, []byte(line+"\n")...)
	}
	if err := writeFile(k.p("/etc/hosts"), hosts, 0o644); err != nil {
		return err
	}
	if k.noExec {
		return nil
	}
	// The kernel's name now, so os.Hostname - and the certificate - see it.
	if err := runCmd("hostname", name); err != nil {
		return err
	}
	// mDNS announces the new name; not fatal if avahi is not running yet.
	_ = runCmd("systemctl", "try-restart", "avahi-daemon")
	fmt.Printf("host name %s (%s.local)\n", name, name)
	return nil
}

var loopback = regexp.MustCompile(`(?m)^127\.0\.1\.1\s.*$`)

const wifiConnection = "deevnet-kit-wifi"

// applyWiFi writes a NetworkManager connection for the owner's network, sets
// the regulatory country, and then blanks wifi_psk in the boot config: the boot
// partition is FAT, readable by anyone holding the card.
func (k *kit) applyWiFi(bc bootSettings, cfgPath string) error {
	// No password: none was asked for, or it was applied on an earlier boot
	// and blanked.
	if bc.WiFiSSID == "" || bc.WiFiPSK == "" {
		return nil
	}
	// A keyfile value ends at a newline and ';' separates list items, so
	// neither can be written into one safely.
	if strings.ContainsAny(bc.WiFiSSID+bc.WiFiPSK, "\n;") {
		return fmt.Errorf("wifi_ssid and wifi_psk cannot contain a semicolon; set this network up by hand with nmcli")
	}
	uuid, err := newUUID()
	if err != nil {
		return err
	}
	conn := fmt.Sprintf(`[connection]
id=%[1]s
uuid=%[2]s
type=wifi
interface-name=wlan0
autoconnect=true

[wifi]
mode=infrastructure
ssid=%[3]s

[wifi-security]
key-mgmt=wpa-psk
psk=%[4]s

[ipv4]
method=auto

[ipv6]
method=auto
`, wifiConnection, uuid, bc.WiFiSSID, bc.WiFiPSK)
	dir := k.p("/etc/NetworkManager/system-connections")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// NetworkManager ignores a keyfile any other user can read.
	if err := writeFile(dir+"/"+wifiConnection+".nmconnection", []byte(conn), 0o600); err != nil {
		return err
	}
	if err := scrubPSK(cfgPath); err != nil {
		return err
	}
	if k.noExec {
		return nil
	}
	// Raspberry Pi OS keeps the radio soft-blocked until a country is set.
	if err := runCmd("raspi-config", "nonint", "do_wifi_country", bc.WiFiCountry); err != nil {
		return err
	}
	if err := runCmd("nmcli", "connection", "reload"); err != nil {
		return err
	}
	// Not fatal: the network may simply not be in range yet. NetworkManager
	// keeps trying, because the connection autoconnects.
	if err := runCmd("nmcli", "connection", "up", wifiConnection); err != nil {
		fmt.Printf("Wi-Fi %q is set up but did not connect yet; NetworkManager keeps trying\n", bc.WiFiSSID)
		return nil
	}
	fmt.Printf("Wi-Fi %q connected\n", bc.WiFiSSID)
	return nil
}

var pskLine = regexp.MustCompile(`(?m)^(\s*wifi_psk\s*=).*$`)

// scrubPSK blanks the Wi-Fi password in the boot config once it has been
// applied, leaving a note why it is empty.
func scrubPSK(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := pskLine.ReplaceAll(raw, []byte("# wifi_psk was applied on first boot and removed from this file.\n${1}"))
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, info.Mode().Perm())
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
