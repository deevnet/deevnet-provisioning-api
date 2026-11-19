package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMosquittoHashVerifies(t *testing.T) {
	h, err := mosquittoHash("kept-from-deevnet")
	if err != nil {
		t.Fatal(err)
	}
	if !mosquittoVerify(h, "kept-from-deevnet") {
		t.Error("a password does not verify against its own hash")
	}
	for _, bad := range []string{"kept-from-deevneT", "", "kept-from-deevnet "} {
		if mosquittoVerify(h, bad) {
			t.Errorf("%q verified", bad)
		}
	}
	if mosquittoVerify("$6$not$ours", "x") || mosquittoVerify("garbage", "x") {
		t.Error("a malformed hash verified")
	}
}

// The move from Deevnet in two commands: re-create the app's account with the
// password it had there, and export a kit.env that carries it - the same
// MQTT_USERNAME and MQTT_PASSWORD lines the Deevnet kit.env has.
func TestExportCarriesTheAppsBrokerLogin(t *testing.T) {
	k, _ := initKit(t, "tenant=tdemo\nindex=3\n")
	pwFile := filepath.Join(t.TempDir(), "app.pw")
	if err := os.WriteFile(pwFile, []byte("the-password-from-deevnet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := k.accountAdd([]string{"app", "--subscribe", "sensors/+/telemetry", "--password-file", pwFile}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "out")
	if err := k.cmdExport([]string{dir, "--app", "app", "--password-file", pwFile}); err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "kit.env"))
	for _, want := range []string{"MQTT_USERNAME=tdemo-app\n", "MQTT_PASSWORD=the-password-from-deevnet\n", "DEEVNET_TENANT=tdemo\n"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("kit.env lacks %q:\n%s", want, env)
		}
	}
	if info, _ := os.Stat(filepath.Join(dir, "kit.env")); info.Mode().Perm() != 0o600 {
		t.Errorf("kit.env holds a password and is mode %v", info.Mode().Perm())
	}

	// A password the broker would refuse never reaches a file.
	wrong := filepath.Join(t.TempDir(), "wrong.pw")
	_ = os.WriteFile(wrong, []byte("not-it\n"), 0o600)
	dir2 := filepath.Join(t.TempDir(), "out2")
	if err := k.cmdExport([]string{dir2, "--app", "app", "--password-file", wrong}); err == nil {
		t.Fatal("exported with the wrong password")
	}
	if _, err := os.Stat(filepath.Join(dir2, "kit.env")); err == nil {
		t.Error("a kit.env was written with the wrong password")
	}
	if err := k.cmdExport([]string{dir2, "--app", "nobody", "--password-file", pwFile}); err == nil {
		t.Error("exported a login for an account that does not exist")
	}
	if err := k.cmdExport([]string{dir2, "--app", "app"}); err == nil {
		t.Error("--app without --password-file was accepted")
	}

	// Without --app the file still works, and says how to add the login.
	dir3 := filepath.Join(t.TempDir(), "out3")
	if err := k.cmdExport([]string{dir3}); err != nil {
		t.Fatal(err)
	}
	if env, _ := os.ReadFile(filepath.Join(dir3, "kit.env")); strings.Contains(string(env), "MQTT_PASSWORD=") {
		t.Error("a password appeared without --app")
	}
}

// The password stays out of argv: --password-file, and not both.
func TestAccountAddTakesAPasswordFile(t *testing.T) {
	k, _ := initKit(t, "tenant=tdemo\n")
	pwFile := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pwFile, []byte("from-a-file\r\n"), 0o600) // edited on Windows
	if err := k.accountAdd([]string{"dev1", "--device", "dev1", "--publish", "sensors/dev1/telemetry", "--password-file", pwFile}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.appCredentials("dev1", "from-a-file"); err != nil {
		t.Errorf("the file's password is not the account's: %v", err)
	}
	if err := k.accountAdd([]string{"dev2", "--device", "dev2", "--publish", "x", "--password", "a", "--password-file", pwFile}); err == nil {
		t.Error("--password and --password-file together were accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if err := k.accountAdd([]string{"dev3", "--device", "dev3", "--publish", "x", "--password-file", empty}); err == nil {
		t.Error("an empty password file was accepted")
	}
}
