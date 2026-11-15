package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// fakeVMAlert stands in for vmalert -dryRun: it fails, in vmalert's log
// format, on a rule file containing BROKEN.
const fakeVMAlert = `#!/bin/sh
for a in "$@"; do case $a in -rule=*) f=${a#-rule=};; esac; done
if grep -q BROKEN "$f"; then
  printf '2026-11-15T05:03:08.567Z\tinfo\tVictoriaMetrics/app/vmalert/main.go:90\treading rules\n'
  printf '2026-11-15T05:03:08.567Z\tfatal\tVictoriaMetrics/app/vmalert/main.go:116\tfailed to parse "[%s]": errors(1): bad expr BROKEN\n' "$f" >&2
  exit 1
fi
exit 0
`

type alertsEnv struct {
	cfg     config
	reloads atomic.Int32
}

func newAlertsEnv(t *testing.T, users ...tenantFile) *alertsEnv {
	t.Helper()
	root := t.TempDir()
	env := &alertsEnv{}
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/-/reload" {
			env.reloads.Add(1)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(am.Close)

	bin := filepath.Join(root, "vmalert-prod")
	if err := os.WriteFile(bin, []byte(fakeVMAlert), 0o755); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(root, "publisher.pw")
	if err := os.WriteFile(pw, []byte(strings.Repeat("p", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	usersDir := filepath.Join(root, "users.d")
	if err := os.MkdirAll(usersDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		b, _ := json.Marshal(u)
		if err := os.WriteFile(filepath.Join(usersDir, u.Tenant+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env.cfg = config{
		UsersDir: usersDir,
		Alerting: &alertingConfig{
			AlertsDir:             filepath.Join(root, "alerts.d"),
			VMAlertDir:            filepath.Join(root, "vmalert"),
			VMAlertBinary:         bin,
			PortBase:              20000,
			AlertmanagerFile:      filepath.Join(root, "alertmanager.yml"),
			AlertmanagerReloadURL: am.URL + "/-/reload",
			NtfyURL:               "http://127.0.0.1:2586",
			NtfyConfigFile:        filepath.Join(root, "ntfy.yml"),
			PublisherPasswordFile: pw,
			PublisherPasswordPath: "/etc/alertmanager/ntfy-publisher.pw",
			ChangedFile:           filepath.Join(root, "changed"),
		},
	}
	if err := env.cfg.Alerting.validate(); err != nil {
		t.Fatal(err)
	}
	return env
}

func user(name string, index int) tenantFile {
	in, rd := tokens(index)
	return tenantFile{Version: 1, Tenant: name, Index: index, IngestToken: in, ReadToken: rd}
}

func alertsReq(name string, index int, groups ...logauth.AlertGroup) logauth.Request {
	return logauth.Request{Version: logauth.Version, Op: logauth.OpAlerts, Tenant: name, Index: index,
		Alerts: &logauth.Alerts{NotifyPassword: strings.Repeat(string(rune('a'+index)), 48), Groups: groups}}
}

func group(name, typ, topic, part, expr string) logauth.AlertGroup {
	return logauth.AlertGroup{Name: name, Type: typ, Interval: "1m", Topic: topic, Partition: part,
		Rules: []logauth.AlertRule{{Alert: "Fires", Expr: expr, Annotations: map[string]string{"summary": `it's "{{ $value }}"`}}}}
}

// apply is what run() does for an alerts request.
func (e *alertsEnv) apply(t *testing.T, req logauth.Request) error {
	t.Helper()
	if err := req.Validate(); err != nil {
		return err
	}
	if err := putAlerts(context.Background(), e.cfg, req); err != nil {
		return err
	}
	users, err := loadTenants(e.cfg.UsersDir)
	if err != nil {
		t.Fatal(err)
	}
	return regenerateAlerting(context.Background(), e.cfg, users, false)
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAlertsRenderEachTenantsVMAlertDirectory(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2), user("tdemo", 1))
	if err := e.apply(t, alertsReq("eds", 2,
		group("backend", "metrics", "backend", "workloads", "proof_queue > 100"),
		group("doors", "logs", "devices", "devices", `"door open" | stats count() as hits | filter hits:>0`),
	)); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(e.cfg.Alerting.VMAlertDir, "eds")
	if got := strings.TrimSpace(read(t, filepath.Join(dir, "token"))); got != user("eds", 2).ReadToken {
		t.Error("the vmalert token is not eds's read token")
	}
	if got := read(t, filepath.Join(dir, "vmalert.env")); got != "VMALERT_PORT=20002\n" {
		t.Errorf("env = %q", got)
	}
	var rules struct {
		Groups []vmGroup `json:"groups"`
	}
	if err := json.Unmarshal([]byte(read(t, filepath.Join(dir, "rules.yml"))), &rules); err != nil {
		t.Fatalf("the rule file is not JSON (which YAML reads as is): %v", err)
	}
	if len(rules.Groups) != 2 {
		t.Fatalf("groups = %d", len(rules.Groups))
	}
	m, l := rules.Groups[0], rules.Groups[1]
	if m.Type != "prometheus" || len(m.Headers) != 0 || m.Labels["deevnet_topic"] != "backend" {
		t.Errorf("metrics group = %+v", m)
	}
	if l.Type != "vlogs" || len(l.Headers) != 1 || l.Headers[0] != "X-Deevnet-Partition: 2-2" {
		t.Errorf("logs group = %+v", l)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.Alerting.VMAlertDir, "tdemo")); !errors.Is(err, os.ErrNotExist) {
		t.Error("tdemo, with no rules, has a vmalert directory")
	}
	if _, err := os.Stat(e.cfg.Alerting.ChangedFile); err != nil {
		t.Error("the changed file was not touched")
	}
}

func TestAlertmanagerRoutesEachTenantsTopicsToItsOwnTopic(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2), user("tdemo", 1))
	for _, r := range []logauth.Request{
		alertsReq("eds", 2, group("a", "metrics", "backend", "workloads", "x > 1"), group("b", "metrics", "backend", "platform", "y > 1")),
		alertsReq("tdemo", 1, group("a", "metrics", "pager", "workloads", "x > 1")),
	} {
		if err := e.apply(t, r); err != nil {
			t.Fatal(err)
		}
	}
	doc := read(t, e.cfg.Alerting.AlertmanagerFile)
	for _, want := range []string{
		`"tenant=\"eds\""`, `"deevnet_topic=\"backend\""`, `"receiver": "eds-backend"`,
		`"url": "http://127.0.0.1:2586/eds-backend?template=alertmanager"`,
		`"tenant=\"tdemo\""`, `"receiver": "tdemo-pager"`,
		`"password_file": "/etc/alertmanager/ntfy-publisher.pw"`,
		`"receiver": "drop"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("alertmanager.yml lacks %s", want)
		}
	}
	// Two groups on one topic are one route.
	if n := strings.Count(doc, `"receiver": "eds-backend"`); n != 1 {
		t.Errorf("eds-backend routed %d times", n)
	}
	if e.reloads.Load() == 0 {
		t.Error("Alertmanager was not reloaded")
	}
}

func TestNtfyUsersReadOnlyTheirOwnPrefix(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2), user("tdemo", 1))
	if err := e.apply(t, alertsReq("eds", 2)); err != nil {
		t.Fatal(err)
	}
	if err := e.apply(t, alertsReq("tdemo", 1, group("a", "metrics", "x", "workloads", "x > 1"))); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Users  []string `json:"auth-users"`
		Access []string `json:"auth-access"`
	}
	body := read(t, e.cfg.Alerting.NtfyConfigFile)
	if err := json.Unmarshal([]byte(body[strings.Index(body, "{"):]), &doc); err != nil {
		t.Fatal(err)
	}
	wantAccess := []string{"alertmanager:*:wo", "eds:eds-*:ro", "tdemo:tdemo-*:ro"}
	if strings.Join(doc.Access, ",") != strings.Join(wantAccess, ",") {
		t.Errorf("access = %v", doc.Access)
	}
	if len(doc.Users) != 3 {
		t.Fatalf("users = %v", doc.Users)
	}
	// A tenant with no rules yet has its login: the phone subscribes first.
	for _, u := range doc.Users {
		parts := strings.SplitN(u, ":", 3)
		if parts[0] == "eds" && bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte(strings.Repeat("c", 48))) != nil {
			t.Error("eds's hash does not match its password")
		}
		if strings.Contains(u, strings.Repeat("c", 48)) {
			t.Error("a password is in ntfy's users file")
		}
	}
}

func TestAnUnchangedLoginLeavesNtfyAlone(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2))
	if err := e.apply(t, alertsReq("eds", 2)); err != nil {
		t.Fatal(err)
	}
	first := read(t, e.cfg.Alerting.NtfyConfigFile)
	if err := os.Remove(e.cfg.Alerting.ChangedFile); err != nil {
		t.Fatal(err)
	}
	// A rule change, the same password: ntfy's users do not change, so the
	// root unit is not asked to restart it.
	if err := e.apply(t, alertsReq("eds", 2, group("a", "metrics", "x", "workloads", "x > 1"))); err != nil {
		t.Fatal(err)
	}
	if read(t, e.cfg.Alerting.NtfyConfigFile) != first {
		t.Error("ntfy's users changed for a rule change")
	}
	_ = os.Remove(e.cfg.Alerting.ChangedFile)
	users, _ := loadTenants(e.cfg.UsersDir)
	if err := regenerateAlerting(context.Background(), e.cfg, users, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.cfg.Alerting.ChangedFile); !errors.Is(err, os.ErrNotExist) {
		t.Error("a render that changed nothing touched the changed file")
	}
}

func TestRulesVMAlertRefusesComeBackAsInvalid(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2))
	err := e.apply(t, alertsReq("eds", 2, group("a", "metrics", "x", "workloads", "sum(BROKEN")))
	var bad *invalidRules
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v, want invalidRules", err)
	}
	if !strings.Contains(bad.msg, "bad expr BROKEN") || strings.Contains(bad.msg, os.TempDir()) || strings.Contains(bad.msg, "VictoriaMetrics/app") {
		t.Errorf("message = %q", bad.msg)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.Alerting.AlertsDir, "eds.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("refused rules were kept")
	}
}

// The writer checks the routing labels itself, so a rule that sets one is
// refused even if it reaches the far end without the API's check.
func TestTheWriterRefusesARoutingLabelItself(t *testing.T) {
	g := group("a", "metrics", "x", "workloads", "vector(1)")
	g.Rules[0].Labels = map[string]string{"tenant": "tdemo"}
	if _, err := rulesDoc(2, []logauth.AlertGroup{g}); err == nil {
		t.Fatal("rulesDoc rendered a rule labelled tenant")
	}
}

func TestATenantWithoutUsersGetsNoAlerts(t *testing.T) {
	e := newAlertsEnv(t)
	if err := e.apply(t, alertsReq("eds", 2)); !errors.Is(err, errNoUsers) {
		t.Fatalf("err = %v, want errNoUsers", err)
	}
	e2 := newAlertsEnv(t, user("eds", 3))
	if err := e2.apply(t, alertsReq("eds", 2)); !errors.Is(err, errNoUsers) {
		t.Fatalf("another index: err = %v, want errNoUsers", err)
	}
}

func TestRemovingATenantRemovesItsAlerting(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2), user("tdemo", 1))
	for _, r := range []logauth.Request{
		alertsReq("eds", 2, group("a", "metrics", "x", "workloads", "x > 1")),
		alertsReq("tdemo", 1, group("a", "metrics", "x", "workloads", "x > 1")),
	} {
		if err := e.apply(t, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeAlerts(e.cfg, "eds"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.cfg.UsersDir, "eds.json")); err != nil {
		t.Fatal(err)
	}
	users, _ := loadTenants(e.cfg.UsersDir)
	if err := regenerateAlerting(context.Background(), e.cfg, users, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.Alerting.VMAlertDir, "eds")); !errors.Is(err, os.ErrNotExist) {
		t.Error("eds's vmalert directory survived its removal")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.Alerting.VMAlertDir, "tdemo")); err != nil {
		t.Error("tdemo's vmalert directory went with eds's")
	}
	for _, f := range []string{e.cfg.Alerting.NtfyConfigFile, e.cfg.Alerting.AlertmanagerFile} {
		if strings.Contains(read(t, f), `"eds`) {
			t.Errorf("%s still names eds", filepath.Base(f))
		}
	}
}

func TestAnAlertsRequestIsRefusedWithoutAlerting(t *testing.T) {
	cfg := config{UsersDir: t.TempDir()}
	if err := putAlerts(context.Background(), cfg, alertsReq("eds", 2)); !errors.Is(err, errNoAlerting) {
		t.Fatalf("err = %v", err)
	}
	if err := regenerateAlerting(context.Background(), cfg, nil, false); err != nil {
		t.Fatalf("a store without alerting renders nothing and fails nothing: %v", err)
	}
}

// TestTheRealVMAlertLoadsTheRenderedRules runs vmalert's own -dryRun on what
// this program renders, when DEEVNET_TEST_VMALERT names a vmalert binary: the
// JSON-as-YAML rule file, both group types and the partition header.
func TestTheRealVMAlertLoadsTheRenderedRules(t *testing.T) {
	bin := os.Getenv("DEEVNET_TEST_VMALERT")
	if bin == "" {
		t.Skip("DEEVNET_TEST_VMALERT is not set")
	}
	a := &alertingConfig{VMAlertBinary: bin}
	good := []logauth.AlertGroup{
		group("backend", "metrics", "backend", "workloads", "sum(rate(http_requests_total[5m])) by (job) > 1"),
		group("doors", "logs", "devices", "devices", `"door open" | stats count() as hits | filter hits:>0`),
	}
	doc, err := rulesDoc(2, good)
	if err != nil {
		t.Fatal(err)
	}
	if err := dryRun(context.Background(), a, "eds", doc); err != nil {
		t.Fatalf("vmalert refused rules this program rendered: %v", err)
	}
	for name, g := range map[string]logauth.AlertGroup{
		"metricsql": group("bad", "metrics", "x", "workloads", "sum(rate(x[5m]"),
		"logsql":    group("bad", "logs", "x", "workloads", `"door | stats count( as`),
	} {
		doc, err := rulesDoc(2, []logauth.AlertGroup{g})
		if err != nil {
			t.Fatal(err)
		}
		err = dryRun(context.Background(), a, "eds", doc)
		var bad *invalidRules
		if !errors.As(err, &bad) {
			t.Errorf("%s: err = %v, want invalidRules", name, err)
			continue
		}
		if !strings.Contains(bad.msg, `invalid group "bad"`) || strings.Contains(bad.msg, os.TempDir()) {
			t.Errorf("%s: message = %q", name, bad.msg)
		}
		t.Logf("%s: %s", name, bad.msg)
	}
}

// Ansible renders before Alertmanager has started on a first deploy; the API
// must hear about an Alertmanager that is down.
func TestAnAlertmanagerNotYetRunningFailsOnlyARequest(t *testing.T) {
	e := newAlertsEnv(t, user("eds", 2))
	e.cfg.Alerting.AlertmanagerReloadURL = "http://127.0.0.1:1/-/reload"
	if err := e.apply(t, alertsReq("eds", 2, group("a", "metrics", "x", "workloads", "x > 1"))); err == nil {
		t.Fatal("a request succeeded with Alertmanager down")
	}
	_ = os.Remove(e.cfg.Alerting.AlertmanagerFile)
	e.cfg.renderMode = true
	users, _ := loadTenants(e.cfg.UsersDir)
	if err := regenerateAlerting(context.Background(), e.cfg, users, false); err != nil {
		t.Fatalf("a render failed with Alertmanager down: %v", err)
	}
}
