package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two cards at one meetup must not both be raspberrypi.local.
func TestHostnameIsAppliedToHostnameAndHosts(t *testing.T) {
	k := testKit(t)
	if err := os.MkdirAll(k.p("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(k.p("/etc/hosts"), []byte("127.0.0.1\tlocalhost\n127.0.1.1\t\traspberrypi\n"), 0o644)
	if err := k.applyHostname("bench1"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(k.p("/etc/hostname")); string(b) != "bench1\n" {
		t.Errorf("/etc/hostname = %q", b)
	}
	hosts, _ := os.ReadFile(k.p("/etc/hosts"))
	if strings.Contains(string(hosts), "raspberrypi") || !strings.Contains(string(hosts), "127.0.1.1\tbench1") {
		t.Errorf("/etc/hosts = %q", hosts)
	}
	if !strings.Contains(string(hosts), "127.0.0.1\tlocalhost") {
		t.Errorf("localhost was lost: %q", hosts)
	}
}

// The Wi-Fi password lands in a root-only keyfile and leaves the FAT boot
// partition, where anyone holding the card could read it.
func TestWiFiIsWrittenAndThePasswordLeavesTheBootPartition(t *testing.T) {
	k := testKit(t)
	cfg := bootConfig(t, "tenant=tdemo\nwifi_ssid=Home Net\nwifi_psk=correct horse\nwifi_country=US\n")
	bc, err := readBootConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.applyWiFi(bc, cfg); err != nil {
		t.Fatal(err)
	}
	path := k.p("/etc/NetworkManager/system-connections/deevnet-kit-wifi.nmconnection")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("keyfile mode %v, want 0600: NetworkManager ignores a readable one", info.Mode().Perm())
	}
	conn, _ := os.ReadFile(path)
	for _, want := range []string{"ssid=Home Net\n", "psk=correct horse\n", "key-mgmt=wpa-psk", "autoconnect=true"} {
		if !strings.Contains(string(conn), want) {
			t.Errorf("keyfile lacks %q:\n%s", want, conn)
		}
	}
	left, _ := os.ReadFile(cfg)
	if strings.Contains(string(left), "correct horse") {
		t.Errorf("the Wi-Fi password is still on the boot partition:\n%s", left)
	}
	// What is left still parses: the boot config is read again on a re-run.
	if _, err := readBootConfig(cfg); err != nil {
		t.Errorf("the scrubbed file no longer parses: %v", err)
	}
	if !strings.Contains(string(left), "wifi_ssid=Home Net") {
		t.Errorf("the SSID should stay, only the password goes:\n%s", left)
	}
	// A first boot that stopped part way reads the scrubbed file again: that
	// must leave the connection it already wrote alone.
	bc2, _ := readBootConfig(cfg)
	if err := k.applyWiFi(bc2, cfg); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(conn) {
		t.Error("a second pass over the scrubbed config rewrote the Wi-Fi connection")
	}
	_ = filepath.Base(path)
}
