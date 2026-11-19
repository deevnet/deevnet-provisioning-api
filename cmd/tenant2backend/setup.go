package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// setup is the console's stand-in for the Pi's boot partition (CHG-0074).
//
// A Pi's owner writes backend.txt, userconf.txt and ssh on the card before
// its first boot. A virtual machine's disk, or a machine installed from the
// ISO, has no partition to edit, so setup asks the same questions on the
// console, once, before first boot: the tenant, its index and the host name,
// which it writes to the file init reads; and the owner's login, which it
// makes. Nothing else differs, so init and everything after it run as on a Pi.

const (
	// Where setup writes, and where a virtual machine's first boot reads.
	consoleBootConfig = "/etc/backend/backend.txt"
	minPasswordLen    = 8
)

var userRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Names the image already uses, or that would confuse a reader of ps.
var reservedUsers = map[string]bool{
	"root": true, "admin": true, "deevnet": true, "deevnet-kit": true, "backend": true, "tenant2backend": true, "mosquitto": true,
	"victoria": true, "grafana": true, "silo": true, "ntfy": true, "nobody": true, "a_autoprov": true,
}

// setupAnswers is what the owner chose.
type setupAnswers struct {
	Tenant   string
	Index    int
	Hostname string
	User     string
	Password string
	SSHKey   string // one authorized_keys line, or empty
}

// prompter reads answers. secret reads a line without echoing it when the
// input is a terminal.
type prompter struct {
	in     *bufio.Reader
	out    io.Writer
	secret func() (string, error)
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	p := &prompter{in: bufio.NewReader(in), out: out}
	p.secret = p.line
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		p.secret = func() (string, error) {
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(out)
			return string(b), err
		}
	}
	return p
}

func (p *prompter) line() (string, error) {
	s, err := p.in.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// ask repeats a question until check accepts the answer. An empty answer takes
// def, when there is one.
func (p *prompter) ask(q, def string, check func(string) error) (string, error) {
	for {
		if def != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", q, def)
		} else {
			fmt.Fprintf(p.out, "%s: ", q)
		}
		a, err := p.line()
		if err != nil {
			return "", err
		}
		if a == "" {
			a = def
		}
		if err := check(a); err != nil {
			fmt.Fprintf(p.out, "  %v\n", err)
			continue
		}
		return a, nil
	}
}

func (p *prompter) askPassword() (string, error) {
	for {
		fmt.Fprint(p.out, "Password (for the console, sudo and, without a key, SSH): ")
		a, err := p.secret()
		if err != nil {
			return "", err
		}
		if len(a) < minPasswordLen {
			fmt.Fprintf(p.out, "  at least %d characters\n", minPasswordLen)
			continue
		}
		fmt.Fprint(p.out, "The same password again: ")
		b, err := p.secret()
		if err != nil {
			return "", err
		}
		if a != b {
			fmt.Fprintln(p.out, "  the two did not match; again")
			continue
		}
		return a, nil
	}
}

func (k *kit) cmdSetup(in io.Reader, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	cfgPath := fs.String("config", consoleBootConfig, "where to write the settings first boot reads")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := k.p(*cfgPath)
	// Once only: a second run would add a second login, and the settings it
	// wrote are first boot's, which has already read them.
	for _, done := range []string{k.stateFile(), cfg} {
		if _, err := os.Stat(done); err == nil {
			fmt.Fprintf(out, "already set up (%s exists); nothing to do\n", done)
			return nil
		}
	}

	p := newPrompter(in, out)
	fmt.Fprint(out, `
tenant2backend setup: this machine's first boot

These are the settings a Raspberry Pi's owner writes on its card. They are
asked once. Your tenant's name and index are in its terraform output.

`)
	var a setupAnswers
	for {
		var err error
		if a, err = k.askSetup(p); err != nil {
			return err
		}
		fmt.Fprintf(out, "\n  tenant    %s (index %d)\n  host name %s (%s.local)\n  login     %s, %s\n\n",
			a.Tenant, a.Index, a.Hostname, a.Hostname, a.User, signIn(a))
		ok, err := p.ask("Use these? (yes/no)", "yes", func(s string) error {
			if s != "yes" && s != "no" && s != "y" && s != "n" {
				return errors.New("yes or no")
			}
			return nil
		})
		if err != nil {
			return err
		}
		if ok == "yes" || ok == "y" {
			break
		}
		fmt.Fprintln(out, "\nAgain, then.")
	}
	return k.applySetup(a, cfg, out)
}

func signIn(a setupAnswers) string {
	if a.SSHKey != "" {
		return "password on the console, SSH by key only"
	}
	return "password, on the console and over SSH"
}

func (k *kit) askSetup(p *prompter) (setupAnswers, error) {
	var a setupAnswers
	var err error
	if a.Tenant, err = p.ask("Tenant", defaultTenant, func(s string) error {
		if !tenant.ValidName(s) {
			return errors.New("1-8 lowercase letters or digits, starting with a letter")
		}
		return nil
	}); err != nil {
		return a, err
	}
	idx, err := p.ask("Tenant index", "1", func(s string) error {
		if n, err := strconv.Atoi(s); err != nil || n < 1 {
			return errors.New("a whole number, 1 or more")
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	a.Index, _ = strconv.Atoi(idx)
	if a.Hostname, err = p.ask("Host name", a.Tenant+"-kit", func(s string) error {
		if !hostnameRE.MatchString(s) {
			return errors.New("lowercase letters, digits and dashes, not starting or ending with a dash")
		}
		return nil
	}); err != nil {
		return a, err
	}
	if a.User, err = p.ask("Your login name", "", k.checkUser); err != nil {
		return a, err
	}
	if a.Password, err = p.askPassword(); err != nil {
		return a, err
	}
	fmt.Fprintln(p.out, "An SSH public key turns SSH passwords off. Paste one line, or leave it empty.")
	if a.SSHKey, err = p.ask("SSH public key", "", func(s string) error {
		if s == "" {
			return nil
		}
		if _, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s)); err != nil || len(rest) > 0 {
			return errors.New("not one public key line, such as ssh-ed25519 AAAA... you@computer")
		}
		return nil
	}); err != nil {
		return a, err
	}
	return a, nil
}

// checkUser refuses a name the image uses, and one already on the machine.
func (k *kit) checkUser(s string) error {
	if !userRE.MatchString(s) {
		return errors.New("lowercase letters, digits and dashes, starting with a letter")
	}
	if reservedUsers[s] {
		return fmt.Errorf("%s is used by the image; choose another", s)
	}
	passwd, _ := os.ReadFile(k.p("/etc/passwd"))
	for _, l := range strings.Split(string(passwd), "\n") {
		if strings.HasPrefix(l, s+":") {
			return fmt.Errorf("%s already exists; choose another", s)
		}
	}
	return nil
}

// applySetup makes the login, then writes the settings. The settings file is
// what says setup ran, so it goes last: a setup that fails part way is asked
// again on the next boot, and a login it made by then is refused by name, so
// the owner chooses another rather than gaining a second account silently.
func (k *kit) applySetup(a setupAnswers, cfg string, out io.Writer) error {
	if err := k.makeLogin(a); err != nil {
		return fmt.Errorf("making the login %s: %w", a.User, err)
	}
	body := fmt.Sprintf(`# tenant2backend - written by tenant2backend setup on the console, and read ONCE by
# first boot (tenant2backend init), as a Pi reads its boot partition's copy.
tenant=%s
index=%d
hostname=%s
`, a.Tenant, a.Index, a.Hostname)
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		return err
	}
	if err := writeFile(cfg, []byte(body), 0o644); err != nil {
		return err
	}
	// Read back through init's own parser, so a file init would refuse is
	// caught here, on the console, rather than in first boot's journal.
	if _, err := readBootConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nSet up. First boot continues; then sign in as %s, at %s.local or this console.\n\n", a.User, a.Hostname)
	return nil
}

// makeLogin adds the owner's user, in sudo, with the password, and the SSH key
// if one was given. With a key, SSH takes keys only.
func (k *kit) makeLogin(a setupAnswers) error {
	if !k.noExec {
		if err := runCmd("useradd", "--create-home", "--shell", "/bin/bash", "--groups", "sudo", a.User); err != nil {
			return err
		}
		if err := runCmdInput(a.User+":"+a.Password+"\n", "chpasswd"); err != nil {
			return err
		}
	}
	if a.SSHKey == "" {
		return nil
	}
	sshDir := k.p(filepath.Join("/home", a.User, ".ssh"))
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(sshDir, "authorized_keys"), []byte(a.SSHKey+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.MkdirAll(k.p("/etc/ssh/sshd_config.d"), 0o755); err != nil {
		return err
	}
	if err := writeFile(k.p("/etc/ssh/sshd_config.d/backend.conf"),
		[]byte("# tenant2backend setup: the owner gave an SSH key, so SSH takes keys only.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"), 0o644); err != nil {
		return err
	}
	if k.noOwner || k.noExec {
		return nil
	}
	if err := runCmd("chown", "-R", a.User+":"+a.User, sshDir); err != nil {
		return err
	}
	// SSH is already running by now, with passwords on: it takes the
	// drop-in only when it rereads its configuration.
	return runCmd("systemctl", "try-reload-or-restart", "ssh")
}

// runCmdInput runs a command with input on its stdin: chpasswd, so the
// password is never on a command line. A variable, like runCmd.
var runCmdInput = func(input string, argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return nil
}
