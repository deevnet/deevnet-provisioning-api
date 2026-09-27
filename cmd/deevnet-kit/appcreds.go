package main

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// The app's own broker login in kit.env.
//
// The account belongs to the tenant, not to the site: on Deevnet it is a
// deevnet_iot_broker_account, and moving to the Pi re-creates it here with the
// SAME password, as devices keep theirs. So MQTT_USERNAME and MQTT_PASSWORD are
// the same two lines on both, and the app's environment really is one file.
// The kit keeps only the password's hash, so it cannot print the password
// back; the owner hands it in from a file, and it is checked against the hash
// before it is written anywhere.

// appCreds is the app's broker login, or empty for none.
type appCreds struct{ User, Password string }

// readPasswordFile reads the first line of path, or of stdin for "-". A file
// rather than a flag, so the password stays out of shell history and ps.
func readPasswordFile(path string) (string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", fmt.Errorf("%s: no password on its first line", path)
	}
	return pw, nil
}

// appFlags reads --app NAME --password-file FILE, which env and export share.
func (k *kit) appFlags(cmd string, args []string) ([]string, appCreds, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	app := fs.String("app", "", "the app's broker account, to write MQTT_USERNAME and MQTT_PASSWORD")
	pwFile := fs.String("password-file", "", "that account's password, first line of the file; - for stdin")
	if err := fs.Parse(args); err != nil {
		return nil, appCreds{}, err
	}
	if (*app == "") != (*pwFile == "") {
		return nil, appCreds{}, fmt.Errorf("--app and --password-file go together")
	}
	if *app == "" {
		return fs.Args(), appCreds{}, nil
	}
	pw, err := readPasswordFile(*pwFile)
	if err != nil {
		return nil, appCreds{}, err
	}
	creds, err := k.appCredentials(*app, pw)
	return fs.Args(), creds, err
}

// appCredentials checks pw against the account's stored hash, so a kit.env
// can never carry a password the broker would refuse.
func (k *kit) appCredentials(name, pw string) (appCreds, error) {
	st, err := k.loadState()
	if err != nil {
		return appCreds{}, err
	}
	raw, err := os.ReadFile(k.accountFile(name))
	if errors.Is(err, os.ErrNotExist) {
		return appCreds{}, fmt.Errorf("no account %q; create it first: deevnet-kit account add %s ... --password-file FILE", name, name)
	}
	if err != nil {
		return appCreds{}, err
	}
	var a account
	if err := json.Unmarshal(raw, &a); err != nil {
		return appCreds{}, err
	}
	if !mosquittoVerify(a.PasswordHash, pw) {
		return appCreds{}, fmt.Errorf("that is not account %q's password", name)
	}
	return appCreds{User: username(st, name), Password: pw}, nil
}

// mosquittoVerify checks a password against a mosquittoHash ($7$iter$salt$key).
func mosquittoVerify(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[1] != "7" {
		return false
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[3])
	want, err2 := base64.StdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha512.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// appEnv is the two lines, or a note saying how to add them.
func appEnv(c appCreds) string {
	if c.User == "" {
		return "# The app's broker login: deevnet-kit export DIR --app NAME --password-file FILE\n"
	}
	return fmt.Sprintf("MQTT_USERNAME=%s\nMQTT_PASSWORD=%s\n", c.User, c.Password)
}
