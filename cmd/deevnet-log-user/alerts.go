package main

// Tenant alerting on the observability store (ADR-0023 §5, CHG-0071).
//
// This program keeps each tenant's alerting state in alerts.d/<tenant>.json
// and renders three things from every tenant's state:
//
//   - a directory per tenant with rules, for that tenant's vmalert: its rule
//     file, its read token and its port;
//   - Alertmanager's configuration: one route per tenant and topic, to that
//     tenant's ntfy topic;
//   - ntfy's users and access list: each tenant reads <tenant>-*, and only
//     Alertmanager publishes.
//
// It stays unprivileged. Alertmanager reloads over its loopback listener. For
// the rest it touches changed_file, and a root path unit on the host starts,
// reloads or stops each tenant's vmalert and restarts ntfy when its users
// change: neither can be told to re-read from here.
//
// Every document is written as JSON, which YAML reads as it is, so a tenant's
// text - a rule expression, an annotation - is always a quoted string and
// cannot break out of its field.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// alertingConfig is the alerting half of the writer's configuration. Absent,
// the store has no alerting and an alerts request is refused.
type alertingConfig struct {
	// AlertsDir holds one file per tenant, owned by this program.
	AlertsDir string `json:"alerts_dir"`
	// VMAlertDir holds the directory each tenant's vmalert reads.
	VMAlertDir string `json:"vmalert_dir"`
	// VMAlertBinary checks a tenant's rules with -dryRun before they are kept.
	VMAlertBinary string `json:"vmalert_binary"`
	// PortBase plus the tenant's index is its vmalert's loopback port.
	PortBase int `json:"vmalert_port_base"`

	AlertmanagerFile      string `json:"alertmanager_file"`
	AlertmanagerReloadURL string `json:"alertmanager_reload_url"`
	// NtfyURL is ntfy's loopback listener, as Alertmanager reaches it.
	NtfyURL        string `json:"ntfy_url"`
	NtfyConfigFile string `json:"ntfy_config_file"`
	// PublisherPasswordFile is Alertmanager's ntfy password on this host,
	// read here only to hash it for ntfy. PublisherPasswordPath is the same
	// file as Alertmanager's container sees it.
	PublisherPasswordFile string `json:"publisher_password_file"`
	PublisherPasswordPath string `json:"publisher_password_path"`
	// ChangedFile is touched when a vmalert directory or ntfy's users change.
	ChangedFile string `json:"changed_file"`
}

func (a *alertingConfig) validate() error {
	if a == nil {
		return nil
	}
	for k, v := range map[string]string{
		"alerts_dir": a.AlertsDir, "vmalert_dir": a.VMAlertDir, "vmalert_binary": a.VMAlertBinary,
		"alertmanager_file": a.AlertmanagerFile, "alertmanager_reload_url": a.AlertmanagerReloadURL,
		"ntfy_url": a.NtfyURL, "ntfy_config_file": a.NtfyConfigFile,
		"publisher_password_file": a.PublisherPasswordFile, "publisher_password_path": a.PublisherPasswordPath,
		"changed_file": a.ChangedFile,
	} {
		if v == "" {
			return fmt.Errorf("alerting.%s is required", k)
		}
	}
	if a.PortBase < 1024 || a.PortBase+logauth.MaxIndex > 65535 {
		return fmt.Errorf("alerting.vmalert_port_base %d leaves no room for every tenant's port", a.PortBase)
	}
	return nil
}

// publisherUser is Alertmanager's ntfy login. Tenant names are at most eight
// characters, so no tenant can be called this.
const publisherUser = "alertmanager"

// alertsFile is one tenant's alerting state, as this program stores it. The
// ntfy password is not kept, only its hash.
type alertsFile struct {
	Version    int                  `json:"version"`
	Tenant     string               `json:"tenant"`
	Index      int                  `json:"index"`
	NotifyHash string               `json:"notify_hash"`
	Groups     []logauth.AlertGroup `json:"groups"`
}

// putAlerts handles an OpAlerts request. A refusal of the tenant's own rules
// comes back as errInvalidRules, whose text goes to the tenant.
func putAlerts(ctx context.Context, cfg config, req logauth.Request) error {
	a := cfg.Alerting
	if a == nil {
		return errNoAlerting
	}
	// The tenant's vmalert reads with the read token the put wrote. Without
	// it there is nothing to run the rules as.
	users, err := loadTenants(cfg.UsersDir)
	if err != nil {
		return err
	}
	var own *tenantFile
	for i := range users {
		if users[i].Tenant == req.Tenant {
			own = &users[i]
		}
	}
	if own == nil || own.Index != req.Index {
		return errNoUsers
	}

	path := filepath.Join(a.AlertsDir, req.Tenant+".json")
	hash := ""
	if prev, err := readAlertsFile(path); err == nil && bcrypt.CompareHashAndPassword([]byte(prev.NotifyHash), []byte(req.Alerts.NotifyPassword)) == nil {
		// Unchanged password, unchanged hash: ntfy is not restarted for a
		// rule change.
		hash = prev.NotifyHash
	} else {
		h, err := bcrypt.GenerateFromPassword([]byte(req.Alerts.NotifyPassword), 10)
		if err != nil {
			return err
		}
		hash = string(h)
	}

	if len(req.Alerts.Groups) > 0 {
		doc, err := rulesDoc(req.Index, req.Alerts.Groups)
		if err != nil {
			return err
		}
		if err := dryRun(ctx, a, req.Tenant, doc); err != nil {
			return err
		}
	}

	body, err := json.MarshalIndent(alertsFile{
		Version: logauth.Version, Tenant: req.Tenant, Index: req.Index,
		NotifyHash: hash, Groups: req.Alerts.Groups,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.AlertsDir, 0o700); err != nil {
		return err
	}
	return writeFile(path, append(body, '\n'), 0o600)
}

var (
	errNoAlerting = errors.New("this store has no alerting")
	errNoUsers    = errors.New("the tenant has no users on this store; its log tokens are written first")
)

// invalidRules is vmalert refusing a tenant's rules.
type invalidRules struct{ msg string }

func (e *invalidRules) Error() string { return e.msg }

// removeAlerts drops a tenant's alerting state, with its users (OpDelete).
func removeAlerts(cfg config, tenant string) error {
	if cfg.Alerting == nil {
		return nil
	}
	err := os.Remove(filepath.Join(cfg.Alerting.AlertsDir, tenant+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readAlertsFile(path string) (alertsFile, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return alertsFile{}, err
	}
	var f alertsFile
	if err := json.Unmarshal(body, &f); err != nil {
		return alertsFile{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return f, nil
}

func loadAlerts(dir string) ([]alertsFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []alertsFile
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		f, err := readAlertsFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tenant < out[j].Tenant })
	return out, nil
}

// vmalert's rule file.
type vmGroup struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Interval string            `json:"interval"`
	Labels   map[string]string `json:"labels"`
	Headers  []string          `json:"headers,omitempty"`
	Rules    []vmRule          `json:"rules"`
}

type vmRule struct {
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         string            `json:"for,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// rulesDoc renders one tenant's rule file. Each group is validated again
// here: this is the last check before vmalert, so a rule that sets the
// routing labels is refused even if the API let it through.
func rulesDoc(index int, groups []logauth.AlertGroup) ([]byte, error) {
	var out struct {
		Groups []vmGroup `json:"groups"`
	}
	for _, g := range groups {
		if err := g.Validate(); err != nil {
			return nil, err
		}
		vg := vmGroup{
			Name:     g.Name,
			Type:     "prometheus",
			Interval: g.Interval,
			// The topic is a group label; the tenant label is vmalert's
			// -external.label. Neither can be set by a rule (Validate).
			Labels: map[string]string{logauth.LabelTopic: g.Topic},
		}
		if g.Type == logauth.AlertTypeLogs {
			vg.Type = "vlogs"
		}
		// The workloads partition is the read user's default. Any other is
		// chosen with the selector header, which vmauth matches only among
		// this tenant's own partitions.
		if p := logauth.PartitionProject(g.Partition); p != 0 {
			vg.Headers = []string{partition(index, p)}
		}
		for _, r := range g.Rules {
			vg.Rules = append(vg.Rules, vmRule(r))
		}
		out.Groups = append(out.Groups, vg)
	}
	return json.MarshalIndent(out, "", "  ")
}

// dryRun has vmalert parse the tenant's rules, templates included, without
// running them.
func dryRun(ctx context.Context, a *alertingConfig, tenant string, doc []byte) error {
	tmp, err := os.CreateTemp("", "rules-"+tenant+"-*.yml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(doc); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.VMAlertBinary, "-dryRun", "-rule="+tmp.Name()).CombinedOutput()
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return fmt.Errorf("running %s: %w", a.VMAlertBinary, err)
	}
	return &invalidRules{msg: dryRunMessage(string(out), tmp.Name())}
}

// logPrefix is vmalert's own log line prefix: time, level and source.
var logPrefix = regexp.MustCompile(`^\S+\t(info|warn|error|fatal|panic)\t\S+\t`)

// dryRunMessage keeps vmalert's fatal line and the lines that continue it,
// which carry the group, the rule and the parse error, without the log prefix
// or this host's temporary path, bounded for an API response.
func dryRunMessage(out, path string) string {
	var lines []string
	inFatal := false
	for _, l := range strings.Split(out, "\n") {
		m := logPrefix.FindStringSubmatchIndex(l)
		switch {
		case m != nil && (l[m[2]:m[3]] == "fatal" || l[m[2]:m[3]] == "error" || l[m[2]:m[3]] == "panic"):
			inFatal = true
			lines = append(lines, l[m[1]:])
		case m != nil:
			inFatal = false
		case inFatal && strings.TrimSpace(l) != "":
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	msg := strings.Join(lines, " ")
	if msg == "" {
		msg = "vmalert refused the rules"
	}
	msg = strings.ReplaceAll(msg, path, "rules")
	const max = 800
	if len(msg) > max {
		msg = msg[:max] + "…"
	}
	return "the rules do not load: " + msg
}

// regenerateAlerting renders every tenant's vmalert directory, Alertmanager's
// configuration and ntfy's users from the alerting files.
func regenerateAlerting(ctx context.Context, cfg config, users []tenantFile, noReload bool) error {
	a := cfg.Alerting
	if a == nil {
		return nil
	}
	states, err := loadAlerts(a.AlertsDir)
	if err != nil {
		return err
	}
	// A tenant runs alerts only with users here, under the same index: its
	// vmalert reads as the read user.
	byName := map[string]tenantFile{}
	for _, u := range users {
		byName[u.Tenant] = u
	}
	var live []alertsFile
	for _, s := range states {
		if u, ok := byName[s.Tenant]; ok && u.Index == s.Index {
			live = append(live, s)
		}
	}

	pubHash, err := publisherHash(a)
	if err != nil {
		return err
	}

	ntfyDoc, err := ntfyUsersDoc(pubHash, live)
	if err != nil {
		return err
	}
	ntfyChanged, err := writeIfChanged(a.NtfyConfigFile, ntfyDoc, 0o640)
	if err != nil {
		return err
	}

	amDoc, err := alertmanagerDoc(a, live)
	if err != nil {
		return err
	}
	amChanged, err := writeIfChanged(a.AlertmanagerFile, amDoc, 0o640)
	if err != nil {
		return err
	}

	dirsChanged, err := renderVMAlertDirs(a, live, byName)
	if err != nil {
		return err
	}

	if ntfyChanged || dirsChanged {
		if err := writeFile(a.ChangedFile, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
			return err
		}
	}
	if amChanged && !noReload {
		err := reloadAlertmanager(ctx, a.AlertmanagerReloadURL)
		var down *alertmanagerDown
		if errors.As(err, &down) && cfg.renderMode {
			fmt.Fprintln(os.Stderr, "Alertmanager is not running; it reads the new configuration when it starts:", err)
			return nil
		}
		return err
	}
	return nil
}

// publisherHash is the bcrypt hash of Alertmanager's ntfy password, kept
// beside the tenant files and made again only when the password changes, so
// that ntfy's users file - and ntfy - stay put across renders.
func publisherHash(a *alertingConfig) (string, error) {
	pw, err := os.ReadFile(a.PublisherPasswordFile)
	if err != nil {
		return "", fmt.Errorf("reading the publisher password: %w", err)
	}
	pw = bytes.TrimSpace(pw)
	if len(pw) < logauth.MinNotifyPasswordLen {
		return "", errors.New("the publisher password is too short")
	}
	cache := filepath.Join(a.AlertsDir, ".publisher.hash")
	if h, err := os.ReadFile(cache); err == nil && bcrypt.CompareHashAndPassword(bytes.TrimSpace(h), pw) == nil {
		return string(bytes.TrimSpace(h)), nil
	}
	h, err := bcrypt.GenerateFromPassword(pw, 10)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(a.AlertsDir, 0o700); err != nil {
		return "", err
	}
	if err := writeFile(cache, append(h, '\n'), 0o600); err != nil {
		return "", err
	}
	return string(h), nil
}

// ntfyUsersDoc is ntfy's declared users and access list. ntfy deletes a
// declared user that is no longer listed (CHG-0071, Step 1, finding 3), so
// this list is the whole of ntfy's users and nothing adds one by hand.
func ntfyUsersDoc(pubHash string, live []alertsFile) ([]byte, error) {
	doc := struct {
		Users  []string `json:"auth-users"`
		Access []string `json:"auth-access"`
	}{
		Users:  []string{publisherUser + ":" + pubHash + ":user"},
		Access: []string{publisherUser + ":*:wo"},
	}
	for _, s := range live {
		if !strings.HasPrefix(s.NotifyHash, "$2") || strings.ContainsAny(s.NotifyHash, ": \n") {
			return nil, fmt.Errorf("tenant %s has no usable ntfy hash", s.Tenant)
		}
		doc.Users = append(doc.Users, s.Tenant+":"+s.NotifyHash+":user")
		// Tenant names have no dash, so <tenant>-* matches this tenant's
		// topics and no other's.
		doc.Access = append(doc.Access, s.Tenant+":"+s.Tenant+"-*:ro")
	}
	return marshalDoc("ntfy's users and access list", doc)
}

// alertmanagerDoc is Alertmanager's whole configuration: a route per tenant
// and topic, and a receiver that publishes to that tenant's topic.
func alertmanagerDoc(a *alertingConfig, live []alertsFile) ([]byte, error) {
	type basicAuth struct {
		Username     string `json:"username"`
		PasswordFile string `json:"password_file"`
	}
	type webhook struct {
		URL          string `json:"url"`
		SendResolved bool   `json:"send_resolved"`
		HTTPConfig   struct {
			BasicAuth basicAuth `json:"basic_auth"`
		} `json:"http_config"`
	}
	type receiver struct {
		Name     string    `json:"name"`
		Webhooks []webhook `json:"webhook_configs,omitempty"`
	}
	type route struct {
		Matchers []string `json:"matchers"`
		Receiver string   `json:"receiver"`
	}
	doc := struct {
		Route struct {
			Receiver       string   `json:"receiver"`
			GroupBy        []string `json:"group_by"`
			GroupWait      string   `json:"group_wait"`
			GroupInterval  string   `json:"group_interval"`
			RepeatInterval string   `json:"repeat_interval"`
			Routes         []route  `json:"routes"`
		} `json:"route"`
		Receivers []receiver `json:"receivers"`
	}{}
	// An alert that matches no tenant's route is dropped, not delivered
	// anywhere.
	doc.Route.Receiver = "drop"
	doc.Route.GroupBy = []string{logauth.LabelTenant, logauth.LabelTopic, "alertname"}
	doc.Route.GroupWait = "30s"
	doc.Route.GroupInterval = "5m"
	doc.Route.RepeatInterval = "4h"
	doc.Route.Routes = []route{}
	doc.Receivers = []receiver{{Name: "drop"}}

	base := strings.TrimRight(a.NtfyURL, "/")
	for _, s := range live {
		topics := map[string]bool{}
		for _, g := range s.Groups {
			topics[g.Topic] = true
		}
		var names []string
		for t := range topics {
			if !logauth.ValidTopic(t) {
				return nil, fmt.Errorf("tenant %s has an invalid topic", s.Tenant)
			}
			names = append(names, t)
		}
		sort.Strings(names)
		for _, t := range names {
			topic := s.Tenant + "-" + t
			doc.Route.Routes = append(doc.Route.Routes, route{
				Matchers: []string{
					fmt.Sprintf("%s=%q", logauth.LabelTenant, s.Tenant),
					fmt.Sprintf("%s=%q", logauth.LabelTopic, t),
				},
				Receiver: topic,
			})
			w := webhook{URL: base + "/" + topic + "?template=alertmanager", SendResolved: true}
			w.HTTPConfig.BasicAuth = basicAuth{Username: publisherUser, PasswordFile: a.PublisherPasswordPath}
			doc.Receivers = append(doc.Receivers, receiver{Name: topic, Webhooks: []webhook{w}})
		}
	}
	return marshalDoc("Alertmanager's configuration", doc)
}

// renderVMAlertDirs writes a directory for each tenant with rules and removes
// the directory of any tenant without. It reports whether anything changed.
func renderVMAlertDirs(a *alertingConfig, live []alertsFile, users map[string]tenantFile) (bool, error) {
	if err := os.MkdirAll(a.VMAlertDir, 0o755); err != nil {
		return false, err
	}
	changed := false
	want := map[string]bool{}
	for _, s := range live {
		if len(s.Groups) == 0 {
			continue
		}
		want[s.Tenant] = true
		dir := filepath.Join(a.VMAlertDir, s.Tenant)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return false, err
		}
		doc, err := rulesDoc(s.Index, s.Groups)
		if err != nil {
			return false, err
		}
		files := []struct {
			name string
			body []byte
			mode os.FileMode
		}{
			{"rules.yml", append(doc, '\n'), 0o640},
			// The read token: the tenant's vmalert queries as the tenant.
			// Group-readable: vmalert runs as its own user in this
			// program's group, not as root.
			{"token", []byte(users[s.Tenant].ReadToken + "\n"), 0o640},
			{"vmalert.env", []byte("VMALERT_PORT=" + strconv.Itoa(a.PortBase+s.Index) + "\n"), 0o640},
		}
		for _, f := range files {
			c, err := writeIfChanged(filepath.Join(dir, f.name), f.body, f.mode)
			if err != nil {
				return false, err
			}
			changed = changed || c
		}
	}
	entries, err := os.ReadDir(a.VMAlertDir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		// Only directories named like a tenant are this program's.
		if !e.IsDir() || !tenantNameRE.MatchString(e.Name()) || want[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(a.VMAlertDir, e.Name())); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

var tenantNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`)

func marshalDoc(what string, doc any) ([]byte, error) {
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding %s: %w", what, err)
	}
	head := []byte("# Generated by deevnet-log-user from the Deevnet API's alerting state. Do not edit.\n")
	return append(append(head, body...), '\n'), nil
}

// writeIfChanged writes only a file whose content differs, and reports it.
func writeIfChanged(path string, body []byte, mode os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, body) {
		return false, nil
	}
	if err := writeFile(path, body, mode); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	return true, nil
}

// alertmanagerDown is an Alertmanager that did not answer at all, as opposed
// to one that answered and refused the configuration.
type alertmanagerDown struct{ err error }

func (e *alertmanagerDown) Error() string { return "asking Alertmanager to reload: " + e.err.Error() }
func (e *alertmanagerDown) Unwrap() error { return e.err }

// reloadAlertmanager asks Alertmanager to re-read its configuration. A
// configuration it refuses leaves it running the previous one, and the
// refusal is this request's failure.
func reloadAlertmanager(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &alertmanagerDown{err}
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Alertmanager refused the reload: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
