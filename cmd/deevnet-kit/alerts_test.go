package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
)

// exported is what `terraform output -json alert_rules` prints for tdemo's
// alerts.tf: every attribute present, the ones not set as null.
const exported = `{
  "groups": [
    {
      "interval": "1m",
      "name": "backend",
      "partition": "workloads",
      "rules": [
        {
          "alert": "QueueBacklog",
          "annotations": {"summary": "The backend's queue is {{ $value }} deep"},
          "expr": "backend_queue_depth > 100",
          "for": "5m",
          "labels": {"severity": "page"}
        }
      ],
      "topic": "backend",
      "type": "metrics"
    },
    {
      "interval": "1m",
      "name": "devices",
      "partition": "devices",
      "rules": [
        {
          "alert": "DeviceError",
          "annotations": {"summary": "{{ $labels.device }} logged {{ $value }} errors"},
          "expr": "error | stats by (device) count() as hits | filter hits:>0",
          "for": null,
          "labels": null
        }
      ],
      "topic": "devices",
      "type": "logs"
    }
  ]
}`

func TestAlertsImportReadsTheTerraformExport(t *testing.T) {
	groups, err := readAlertsImport(strings.NewReader(exported))
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[1].Rules[0].For != "" || groups[1].Rules[0].Labels != nil || groups[0].Rules[0].For != "5m" {
		t.Fatalf("groups %+v", groups)
	}
	a := logauth.Alerts{NotifyPassword: strings.Repeat("a", 48), Groups: groups}
	if err := a.Validate(); err != nil {
		t.Fatalf("the export does not validate: %v", err)
	}
}

func TestAlertsImportRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": strings.Replace(exported, `"topic": "backend"`, `"topic": "backend", "ntfy_topic": "tdemo-backend"`, 1),
		"no groups":     `{"rules": []}`,
		"not json":      `groups = []`,
	} {
		if _, err := readAlertsImport(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The kit sends the writer the request the API sends, with the card's own
// phone login, and keeps the groups only once the writer has taken them.
func TestAlertsImportSendsTheAPIsRequest(t *testing.T) {
	k, st := initKit(t, "tenant=tdemo\nindex=1\n")
	k.noExec = false
	var sent logauth.Request
	var argv []string
	stubRunWithInput(t, func(body []byte, a ...string) ([]byte, error) {
		argv = a
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Fatal(err)
		}
		return []byte(`{"version":1,"ok":true}` + "\n"), nil
	})

	in := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(in, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := k.cmdAlerts(&out, []string{"import", in}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "runuser -u victoria -- /usr/local/bin/deevnet-log-user" {
		t.Errorf("ran %v", argv)
	}
	if sent.Op != logauth.OpAlerts || sent.Tenant != "tdemo" || sent.Index != 1 || sent.Alerts == nil ||
		sent.Alerts.NotifyPassword != st.NotifyPassword || len(sent.Alerts.Groups) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	if err := sent.Validate(); err != nil {
		t.Errorf("the request the kit sends does not validate: %v", err)
	}
	groups, err := k.loadAlerts()
	if err != nil || len(groups) != 2 {
		t.Fatalf("kept %v, %v", groups, err)
	}

	var list bytes.Buffer
	if err := k.cmdAlerts(&list, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list.String(), "tdemo-backend") || !strings.Contains(list.String(), "tdemo-devices") {
		t.Errorf("list:\n%s", list.String())
	}
}

// A group the writer refuses is not kept, and the owner sees vmalert's reason.
func TestAlertsImportSurfacesTheWritersRefusal(t *testing.T) {
	k, _ := initKit(t, "tenant=tdemo\nindex=1\n")
	k.noExec = false
	stubRunWithInput(t, func([]byte, ...string) ([]byte, error) {
		return []byte(`{"version":1,"ok":false,"invalid":true,"error":"group \"backend\": unparsable expr"}`), os.ErrInvalid
	})
	err := k.putAlerts(mustState(t, k), []logauth.AlertGroup{{Name: "backend", Type: "metrics", Interval: "1m", Topic: "backend",
		Partition: "workloads", Rules: []logauth.AlertRule{{Alert: "X", Expr: "sum((x"}}}})
	if err == nil || !strings.Contains(err.Error(), "the rules do not load") || !strings.Contains(err.Error(), "unparsable") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(k.alertsFile()); !os.IsNotExist(err) {
		t.Error("a refused import was kept")
	}
}

// A label that routes an alert is refused before the writer is asked.
func TestAlertsImportRefusesARoutingLabel(t *testing.T) {
	k, st := initKit(t, "tenant=tdemo\nindex=1\n")
	groups, err := readAlertsImport(strings.NewReader(strings.Replace(exported, `"severity": "page"`, `"tenant": "eds"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.putAlerts(st, groups); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("err = %v", err)
	}
}

func TestKitEnvCarriesMetricsAndTheNotifyLogin(t *testing.T) {
	k, st := initKit(t, "tenant=tdemo\nindex=1\n")
	env := kitEnv(st, "bench.local", appCreds{})
	for _, want := range []string{
		"METRICS_ENDPOINT=https://bench.local:8427",
		"NOTIFY_URL=https://bench.local\n",
		"NOTIFY_USERNAME=tdemo\n",
		"NOTIFY_PASSWORD=" + st.NotifyPassword + "\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("kit.env lacks %q:\n%s", want, env)
		}
	}
	if len(st.NotifyPassword) < logauth.MinNotifyPasswordLen {
		t.Errorf("notify password %d long", len(st.NotifyPassword))
	}
	// The writer's base file names the metrics store, so it renders the
	// metrics routes it renders on Deevnet.
	var base map[string]string
	if err := json.Unmarshal(mustRead(t, filepath.Join(k.logDir(), "base.json")), &base); err != nil {
		t.Fatal(err)
	}
	if base["metrics_insert"] != metricsInsertURL || base["metrics_select"] != metricsSelectURL {
		t.Errorf("base %v", base)
	}
	if pw := strings.TrimSpace(string(mustRead(t, k.publisherFile()))); pw != st.PublisherPassword || pw == "" {
		t.Errorf("publisher password file %q", pw)
	}
	if ntfy := string(mustRead(t, k.ntfyEnv())); !strings.Contains(ntfy, "NTFY_BASE_URL=https://") {
		t.Errorf("ntfy.env:\n%s", ntfy)
	}
}

func mustState(t *testing.T, k *kit) state {
	t.Helper()
	st, err := k.loadState()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func stubRunWithInput(t *testing.T, f func([]byte, ...string) ([]byte, error)) {
	t.Helper()
	orig := runWithInput
	runWithInput = f
	t.Cleanup(func() { runWithInput = orig })
}
