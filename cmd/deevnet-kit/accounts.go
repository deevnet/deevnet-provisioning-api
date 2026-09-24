package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/deevnet/deevnet-provisioning-api/internal/brokeracct"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// account is one broker account as the kit stores it: the absolute patterns
// and the password's hash, never the password.
type account struct {
	Name         string   `json:"name"`
	Device       string   `json:"device,omitempty"`
	Publish      []string `json:"publish"`
	Subscribe    []string `json:"subscribe"`
	PasswordHash string   `json:"password_hash"`
}

func username(st state, name string) string { return st.Tenant + "-" + name }

// multi is a repeatable flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func (k *kit) cmdAccount(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("account add|list|rm")
	}
	switch args[0] {
	case "add":
		return k.accountAdd(args[1:])
	case "list", "ls":
		return k.accountList()
	case "rm", "delete":
		if len(args) != 2 {
			return fmt.Errorf("account rm takes one name")
		}
		return k.accountRemove(args[1])
	default:
		return fmt.Errorf("unknown account command %q", args[0])
	}
}

func (k *kit) accountAdd(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("account add NAME [--device DEV] [--publish P]... [--subscribe S]... [--password PW]")
	}
	name := args[0]
	fs := flag.NewFlagSet("account add", flag.ContinueOnError)
	device := fs.String("device", "", "the device this account belongs to; empty for a workload account")
	password := fs.String("password", "", "keep this password instead of generating one")
	var pub, sub multi
	fs.Var(&pub, "publish", "a topic pattern relative to the tenant (repeatable)")
	fs.Var(&sub, "subscribe", "a topic pattern relative to the tenant (repeatable)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	st, err := k.loadState()
	if err != nil {
		return err
	}
	a, err := newAccount(st, name, *device, pub, sub)
	if err != nil {
		return err
	}
	if _, err := os.Stat(k.accountFile(name)); err == nil {
		return fmt.Errorf("account %q exists; deevnet-kit account rm %s first", name, name)
	}

	pw := *password
	if pw == "" {
		if pw, err = randomHex(16); err != nil {
			return err
		}
	}
	if a.PasswordHash, err = mosquittoHash(pw); err != nil {
		return err
	}
	if err := writeJSON(k.accountFile(name), a, 0o600); err != nil {
		return err
	}
	if err := k.renderBroker(st, true); err != nil {
		return err
	}

	fmt.Printf("username  %s\n", username(st, name))
	if *password == "" {
		// Printed once, as the API returns it once. The kit keeps only the hash.
		fmt.Printf("password  %s\n", pw)
	}
	fmt.Printf("publish   %s\n", strings.Join(a.Publish, " "))
	fmt.Printf("subscribe %s\n", strings.Join(a.Subscribe, " "))
	return nil
}

// newAccount applies the API's rules, in the API's order
// (internal/tenant/brokeraccounts.go): the name, the prefix, the grant, and the
// reserved log level.
func newAccount(st state, name, device string, pub, sub []string) (account, error) {
	if !tenant.ValidWorkloadName(name) {
		return account{}, fmt.Errorf("account name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	if device != "" && !tenant.ValidWorkloadName(device) {
		return account{}, fmt.Errorf("device name must be 1-20 lowercase alphanumerics or dashes, starting with a letter")
	}
	// Mosquitto's ACL file is line-based. A pattern the API would pass can
	// still carry a control character, and a newline here would be a second
	// line of permissions.
	for _, p := range append(append([]string{}, pub...), sub...) {
		if strings.IndexFunc(p, unicode.IsControl) >= 0 || strings.TrimSpace(p) != p {
			return account{}, fmt.Errorf("a pattern must not contain control characters or surrounding spaces")
		}
	}
	absPub, err := brokeracct.PrefixPatterns(st.Tenant, "publish", pub)
	if err != nil {
		return account{}, err
	}
	absSub, err := brokeracct.PrefixPatterns(st.Tenant, "subscribe", sub)
	if err != nil {
		return account{}, err
	}
	if err := brokeracct.CheckGrant(absPub, absSub); err != nil {
		return account{}, err
	}
	if err := brokeracct.CheckLogGrants(st.Tenant, device, absPub, absSub); err != nil {
		return account{}, err
	}
	return account{Name: name, Device: device, Publish: nonNil(absPub), Subscribe: nonNil(absSub)}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (k *kit) accountFile(name string) string {
	return filepath.Join(k.accountsDir(), name+".json")
}

func (k *kit) accountList() error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	accts, err := k.loadAccounts()
	if err != nil {
		return err
	}
	if len(accts) == 0 {
		fmt.Println("no accounts; deevnet-kit account add NAME --publish PATTERN")
		return nil
	}
	for _, a := range accts {
		dev := "(workload)"
		if a.Device != "" {
			dev = "device " + a.Device
		}
		fmt.Printf("%-28s %s\n", username(st, a.Name), dev)
		for _, p := range a.Publish {
			fmt.Printf("    publish   %s\n", p)
		}
		for _, s := range a.Subscribe {
			fmt.Printf("    subscribe %s\n", s)
		}
	}
	return nil
}

func (k *kit) accountRemove(name string) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if !tenant.ValidWorkloadName(name) {
		return fmt.Errorf("%q is not an account name", name)
	}
	if err := os.Remove(k.accountFile(name)); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no account %q", name)
	} else if err != nil {
		return err
	}
	// Mosquitto 2.0.11 re-checks every connected client against the password
	// file on reload and disconnects one that no longer authenticates, so this
	// takes effect at once - sooner than on Deevnet, where VerneMQ applies a
	// revocation on the client's next connect. Established in a test against
	// Debian's 2.0.11, not read from the documentation.
	return k.renderBroker(st, true)
}

func (k *kit) loadAccounts() ([]account, error) {
	entries, err := os.ReadDir(k.accountsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []account
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(k.accountsDir(), e.Name()))
		if err != nil {
			return nil, err
		}
		var a account
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- Mosquitto ------------------------------------------------------------------------

// renderBroker writes Mosquitto's password and ACL files from the accounts, and
// asks it to reload. Both files are whole-file renders: the accounts
// directory is the source, so a hand edit lasts until the next account change.
func (k *kit) renderBroker(st state, reload bool) error {
	accts, err := k.loadAccounts()
	if err != nil {
		return err
	}
	// Every stored account is checked again before it becomes a permission:
	// the files are root's, but a rule applied only on the way in is a rule
	// a hand edit can skip.
	for _, a := range accts {
		if _, err := newAccount(st, a.Name, a.Device, relative(st, a.Publish), relative(st, a.Subscribe)); err != nil {
			return fmt.Errorf("stored account %q: %w", a.Name, err)
		}
	}
	bridgeHash, err := mosquittoHash(st.BridgePassword)
	if err != nil {
		return err
	}
	passwd, acl := renderMosquitto(st, bridgeHash, accts)
	for _, f := range []struct {
		name string
		body []byte
	}{{"passwd", passwd}, {"acl", acl}} {
		path := filepath.Join(k.mosquittoDir(), f.name)
		if err := writeFile(path, f.body, 0o640); err != nil {
			return err
		}
		if err := k.chown(path, "root", mosquittoUser); err != nil {
			return err
		}
	}
	if !reload || k.noExec {
		return nil
	}
	return runCmd("systemctl", "reload", "mosquitto")
}

// relative strips the tenant prefix the stored patterns carry, so they can be
// put through the same checks as a new account's.
func relative(st state, abs []string) []string {
	out := make([]string, 0, len(abs))
	for _, p := range abs {
		out = append(out, strings.TrimPrefix(p, st.Tenant+"/"))
	}
	return out
}

func renderMosquitto(st state, bridgeHash string, accts []account) (passwd, acl []byte) {
	var pw, ac bytes.Buffer
	ac.WriteString("# Generated by deevnet-kit from /etc/deevnet-kit/accounts. Do not edit;\n")
	ac.WriteString("# use deevnet-kit account. Anything not granted here is denied.\n\n")

	// The bridge reads every device's log topic and nothing else, as it does
	// on Deevnet (ADR-0027 §4).
	fmt.Fprintf(&pw, "%s:%s\n", bridgeUser, bridgeHash)
	fmt.Fprintf(&ac, "user %s\ntopic read +/%s/#\n", bridgeUser, brokeracct.LogLevel)

	for _, a := range accts {
		u := username(st, a.Name)
		fmt.Fprintf(&pw, "%s:%s\n", u, a.PasswordHash)
		fmt.Fprintf(&ac, "\nuser %s\n", u)
		for _, p := range a.Publish {
			fmt.Fprintf(&ac, "topic write %s\n", p)
		}
		for _, s := range a.Subscribe {
			fmt.Fprintf(&ac, "topic read %s\n", s)
		}
	}
	return pw.Bytes(), ac.Bytes()
}

// mosquittoHash is Mosquitto 2's PBKDF2-SHA512 password format, as
// mosquitto_passwd writes it: $7$<iterations>$<base64 salt>$<base64 hash>,
// with a 12-byte salt and a 64-byte key.
func mosquittoHash(password string) (string, error) {
	const iterations = 101 // mosquitto_passwd's default
	salt := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha512.New, password, salt, iterations, sha512.Size)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$7$%d$%s$%s", iterations,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)), nil
}
