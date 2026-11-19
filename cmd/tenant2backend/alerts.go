package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// Alerting on the Pi (CHG-0072) is Deevnet's (ADR-0023 §5, CHG-0071): the
// tenant's rule groups, checked by logauth's rules, dry-run by vmalert and
// rendered by deevnet-log-user into the tenant's vmalert directory,
// Alertmanager's routes and ntfy's users. The kit stands in for the API: it
// sends deevnet-log-user the same request the API sends, so a group the API
// would refuse is refused here, for the same reason.
//
// The groups come from the tenant's own Terraform, exported with
//
//	terraform output -json alert_rules > rules.json
//
// in the shape the provider's deevnet_alert_rule_group holds them, renamed
// into the writer's: {"groups":[{name,type,interval,topic,partition,rules}]}.

// alertsImport is the file `alerts import` reads.
type alertsImport struct {
	Groups []logauth.AlertGroup `json:"groups"`
}

func (k *kit) alertsFile() string    { return filepath.Join(k.etc(), "alerts.json") }
func (k *kit) alertingDir() string   { return filepath.Join(k.etc(), "alerting") }
func (k *kit) publisherFile() string { return filepath.Join(k.alertingDir(), "ntfy-publisher.pw") }
func (k *kit) ntfyEnv() string       { return filepath.Join(k.etc(), "ntfy.env") }

const (
	// ntfy is on 443, as Deevnet's notify_endpoint is, so the phone app's
	// server is the same shape on both.
	ntfyPort = 443
	// The log store's writer, which renders alerting as it renders users.
	logUserBinary = "/usr/local/bin/deevnet-log-user"
)

func (k *kit) cmdAlerts(w io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("alerts import FILE|- | alerts list | alerts clear | alerts sync")
	}
	st, err := k.loadState()
	if err != nil {
		return err
	}
	switch {
	case args[0] == "import" && len(args) == 2:
		var in io.Reader = os.Stdin
		if args[1] != "-" {
			f, err := os.Open(args[1])
			if err != nil {
				return err
			}
			defer f.Close()
			in = f
		}
		groups, err := readAlertsImport(in)
		if err != nil {
			return err
		}
		if err := k.putAlerts(st, groups); err != nil {
			return err
		}
		fmt.Fprintf(w, "%d alert rule group(s) loaded for %s; tenant2backend notify shows the phone's settings\n", len(groups), st.Tenant)
		return nil
	case args[0] == "list" && len(args) == 1:
		groups, err := k.loadAlerts()
		if err != nil {
			return err
		}
		if len(groups) == 0 {
			fmt.Fprintln(w, "no alert rule groups; tenant2backend alerts import rules.json")
			return nil
		}
		for _, g := range groups {
			fmt.Fprintf(w, "%-24s %-7s %-9s every %-4s %2d rule(s) -> %s\n",
				g.Name, g.Type, g.Partition, g.Interval, len(g.Rules), notifyTopic(st, g.Topic))
		}
		return nil
	case args[0] == "clear" && len(args) == 1:
		if err := k.putAlerts(st, nil); err != nil {
			return err
		}
		fmt.Fprintln(w, "alert rule groups removed; the phone's login stays")
		return nil
	case args[0] == "sync" && len(args) == 1:
		// The image's backend-alerting unit, after Alertmanager and ntfy
		// start: the groups this card already holds, written again, which
		// also makes the phone's login on a first boot.
		groups, err := k.loadAlerts()
		if err != nil {
			return err
		}
		return k.putAlerts(st, groups)
	}
	return errors.New("alerts import FILE|- | alerts list | alerts clear | alerts sync")
}

// readAlertsImport decodes the exported groups strictly: a field the writer
// does not know is a mistake in the export, not something to ignore.
func readAlertsImport(r io.Reader) ([]logauth.AlertGroup, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var in alertsImport
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("reading the rule groups: %w (export them with terraform output -json alert_rules)", err)
	}
	if in.Groups == nil {
		return nil, errors.New(`no "groups": export them with terraform output -json alert_rules`)
	}
	return in.Groups, nil
}

// putAlerts sends the tenant's whole alerting state to deevnet-log-user, as
// the API does, and keeps the groups only once it has taken them.
func (k *kit) putAlerts(st state, groups []logauth.AlertGroup) error {
	st, err := k.ensureAlertingSecrets(st)
	if err != nil {
		return err
	}
	if groups == nil {
		groups = []logauth.AlertGroup{}
	}
	req := logauth.Request{Version: logauth.Version, Op: logauth.OpAlerts, Tenant: st.Tenant, Index: st.Index,
		Alerts: &logauth.Alerts{NotifyPassword: st.NotifyPassword, Groups: groups}}
	// The same check the writer makes, here first, for a plain message.
	if err := req.Validate(); err != nil {
		return err
	}
	if !k.noExec {
		body, err := json.Marshal(req)
		if err != nil {
			return err
		}
		out, err := runWithInput(body, "runuser", "-u", storeUser, "--", logUserBinary)
		var resp logauth.Response
		if jerr := json.Unmarshal(bytes.TrimSpace(out), &resp); jerr != nil {
			if err != nil {
				return fmt.Errorf("deevnet-log-user: %w", err)
			}
			return fmt.Errorf("deevnet-log-user answered %q", out)
		}
		if !resp.OK {
			if resp.Invalid {
				return fmt.Errorf("the rules do not load: %s", resp.Message)
			}
			return fmt.Errorf("deevnet-log-user: %s", resp.Message)
		}
	}
	return writeJSON(k.alertsFile(), alertsImport{Groups: groups}, 0o600)
}

func (k *kit) loadAlerts() ([]logauth.AlertGroup, error) {
	b, err := os.ReadFile(k.alertsFile())
	if errors.Is(err, os.ErrNotExist) {
		return []logauth.AlertGroup{}, nil
	}
	if err != nil {
		return nil, err
	}
	var in alertsImport
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("%s: %w", k.alertsFile(), err)
	}
	return in.Groups, nil
}

// ensureAlertingSecrets mints what a card made before alerting lacks: the
// phone's login and Alertmanager's publisher login. It writes them back, and
// writes the publisher's password where the writer and Alertmanager read it.
func (k *kit) ensureAlertingSecrets(st state) (state, error) {
	changed := false
	var err error
	if st.NotifyPassword == "" {
		// The API's length: randomHex(24), 48 letters or digits.
		if st.NotifyPassword, err = randomHex(24); err != nil {
			return st, err
		}
		changed = true
	}
	if st.PublisherPassword == "" {
		if st.PublisherPassword, err = randomHex(32); err != nil {
			return st, err
		}
		changed = true
	}
	if changed {
		if err := writeJSON(k.stateFile(), st, 0o600); err != nil {
			return st, err
		}
	}
	return st, k.writeAlertingFiles(st)
}

// writeAlertingFiles writes the publisher's password, which the writer hashes
// for ntfy and Alertmanager sends, and ntfy's per-card settings.
func (k *kit) writeAlertingFiles(st state) error {
	if st.PublisherPassword == "" {
		return nil
	}
	if err := os.MkdirAll(k.alertingDir(), 0o750); err != nil {
		return err
	}
	if err := writeFile(k.publisherFile(), []byte(st.PublisherPassword+"\n"), 0o640); err != nil {
		return err
	}
	for _, p := range []string{k.alertingDir(), k.publisherFile()} {
		// The writer's files are the store user's; Alertmanager, ntfy and
		// vmalert read them as members of its group, as vmalert does on
		// Deevnet (CHG-0071).
		if err := k.chown(p, storeUser, storeUser); err != nil {
			return err
		}
	}
	return k.writeNtfyEnv(st)
}

// writeNtfyEnv is the part of ntfy's settings that depends on the card: the
// URL the phone subscribes to. The rest is in the unit.
func (k *kit) writeNtfyEnv(st state) error {
	env := fmt.Sprintf("# tenant2backend - generated; ntfy's settings for this card\nNTFY_BASE_URL=%s\n", notifyURL(st, host()))
	return writeFile(k.ntfyEnv(), []byte(env), 0o644)
}

func notifyURL(st state, h string) string { return "https://" + st.appHost("ntfy", h) }

func notifyTopic(st state, topic string) string { return st.Tenant + "-" + topic }

// notifyEnv is kit.env's alerting lines: the same names tdemo's kit_env
// fills from deevnet_tenant's notify_* attributes.
func notifyEnv(st state, h string) string {
	if st.NotifyPassword == "" {
		return "# Alerting is not set up yet: systemctl status backend-alerting\n"
	}
	return fmt.Sprintf("NOTIFY_URL=%s\nNOTIFY_USERNAME=%s\nNOTIFY_PASSWORD=%s\n", notifyURL(st, h), st.Tenant, st.NotifyPassword)
}

// cmdNotify prints what the phone's ntfy app needs, in the shape of tdemo's
// notify output.
func (k *kit) cmdNotify(w io.Writer) error {
	st, err := k.loadState()
	if err != nil {
		return err
	}
	if st.NotifyPassword == "" {
		return errors.New("alerting is not set up yet: sudo tenant2backend alerts sync")
	}
	groups, err := k.loadAlerts()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	topics := []string{}
	for _, g := range groups {
		if t := notifyTopic(st, g.Topic); !seen[t] {
			seen[t] = true
			topics = append(topics, t)
		}
	}
	sort.Strings(topics)
	out, err := json.MarshalIndent(map[string]any{
		"server": notifyURL(st, host()), "username": st.Tenant, "password": st.NotifyPassword, "topics": topics,
	}, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n# The phone needs this card's CA installed, and a network that reaches %s.\n", out, host())
	return err
}

// runWithInput runs a command with body on its stdin and returns its stdout.
// A variable, like runCmd, so a test can see what would run.
var runWithInput = func(body []byte, argv ...string) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w", strings.Join(argv[:min(len(argv), 5)], " "), err)
	}
	return out, nil
}
