package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq3ZtQ7cBzQ5fJgk1oQm7d6wK3m0b4v1mJ8c6s9Xr2T owner@computer"

func runSetup(t *testing.T, k *kit, input string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := k.cmdSetup(strings.NewReader(input), &out, nil)
	return out.String(), err
}

// The console writes what a Pi's owner writes on the boot partition, and
// init's own parser reads it back.
func TestSetupWritesWhatInitReads(t *testing.T) {
	k := testKit(t)
	out, err := runSetup(t, k, "tdemo\n1\ntdemo-vm\nowner\nsecret-pw\nsecret-pw\n\nyes\n")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	bc, err := readBootConfig(k.p(consoleBootConfig))
	if err != nil {
		t.Fatal(err)
	}
	if bc.Tenant != "tdemo" || bc.Index != 1 || bc.Hostname != "tdemo-vm" {
		t.Errorf("init would read %+v", bc)
	}
	if strings.Contains(out, "secret-pw") {
		t.Error("the password was echoed")
	}
	// No key: SSH keeps passwords, so nothing turns them off.
	if _, err := os.Stat(k.p("/etc/ssh/sshd_config.d/deevnet-kit.conf")); err == nil {
		t.Error("SSH passwords turned off with no key to sign in by")
	}
}

// Empty answers take the defaults: tenant pi, index 1, host name <tenant>-kit.
func TestSetupDefaults(t *testing.T) {
	k := testKit(t)
	if out, err := runSetup(t, k, "\n\n\nowner\nsecret-pw\nsecret-pw\n\n\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	bc, err := readBootConfig(k.p(consoleBootConfig))
	if err != nil {
		t.Fatal(err)
	}
	if bc.Tenant != "pi" || bc.Index != 1 || bc.Hostname != "pi-kit" {
		t.Errorf("defaults gave %+v", bc)
	}
}

// A bad answer is asked again, not written.
func TestSetupAsksAgain(t *testing.T) {
	k := testKit(t)
	_ = os.MkdirAll(k.p("/etc"), 0o755)
	_ = os.WriteFile(k.p("/etc/passwd"), []byte("root:x:0:0::/root:/bin/bash\ntaken:x:1000:1000::/home/taken:/bin/bash\n"), 0o644)
	input := strings.Join([]string{
		"Not-A-Tenant", "tdemo", // not a tenant name
		"zero", "0", "2", // not an index
		"-bad-", "tdemo-vm", // not a host name
		"root", "taken", "owner", // reserved, then existing
		"short", "secret-pw", "other-pw", "secret-pw", "secret-pw", // too short, then a mismatch
		"not a key", testKey,
		"maybe", "yes",
	}, "\n") + "\n"
	out, err := runSetup(t, k, input)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"1-8 lowercase", "a whole number", "not starting or ending", "used by the image",
		"already exists", "at least 8", "did not match", "not one public key", "yes or no"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	bc, _ := readBootConfig(k.p(consoleBootConfig))
	if bc.Index != 2 {
		t.Errorf("index %d", bc.Index)
	}
}

// A key turns SSH passwords off, and lands in the owner's authorized_keys.
func TestSetupWithKeyIsKeyOnly(t *testing.T) {
	k := testKit(t)
	if out, err := runSetup(t, k, "tdemo\n1\ntdemo-vm\nowner\nsecret-pw\nsecret-pw\n"+testKey+"\nyes\n"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ak, err := os.ReadFile(k.p("/home/owner/.ssh/authorized_keys"))
	if err != nil || strings.TrimSpace(string(ak)) != testKey {
		t.Errorf("authorized_keys = %q, %v", ak, err)
	}
	conf, _ := os.ReadFile(k.p("/etc/ssh/sshd_config.d/deevnet-kit.conf"))
	if !strings.Contains(string(conf), "PasswordAuthentication no") {
		t.Errorf("sshd drop-in = %q", conf)
	}
}

// "no" starts the questions over.
func TestSetupStartsOver(t *testing.T) {
	k := testKit(t)
	in := "tdemo\n1\nfirst\nowner\nsecret-pw\nsecret-pw\n\nno\n" +
		"tdemo\n1\nsecond\nowner\nsecret-pw\nsecret-pw\n\nyes\n"
	if out, err := runSetup(t, k, in); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	bc, _ := readBootConfig(k.p(consoleBootConfig))
	if bc.Hostname != "second" {
		t.Errorf("host name %q", bc.Hostname)
	}
}

// Once only: a second run would add a second login after first boot read
// the settings.
func TestSetupRunsOnce(t *testing.T) {
	k := testKit(t)
	if _, err := runSetup(t, k, "\n\n\nowner\nsecret-pw\nsecret-pw\n\n\n"); err != nil {
		t.Fatal(err)
	}
	out, err := runSetup(t, k, "")
	if err != nil || !strings.Contains(out, "already set up") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

// Input that ends part way is an error, not a half-written file.
func TestSetupEndOfInput(t *testing.T) {
	k := testKit(t)
	if _, err := runSetup(t, k, "tdemo\n1\n"); err == nil {
		t.Fatal("no error at end of input")
	}
	if _, err := os.Stat(k.p(consoleBootConfig)); err == nil {
		t.Error("settings written from a part answer")
	}
}
