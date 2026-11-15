package server

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func alertingServer(t *testing.T) (http.Handler, *tenanttest.Backends) {
	t.Helper()
	svc, _, b := tenanttest.NewService()
	svc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.Site.NotifyEndpoint = "https://ntfy.mobile.deevnet.net"
	svc.Alerting = b.Alerting()
	return New(Config{Token: "s3cret", DB: fakeDB{}, Logger: svc.Logger, Tenants: svc}), b
}

const backendGroupJSON = `{"type":"metrics","topic":"backend","rules":[{"alert":"QueueBacklog","expr":"backend_queue_depth > 100","for":"5m","annotations":{"summary":"queue is {{ $value }}"}}]}`

func TestCreateReturnsTheNtfyLoginAndAGetDoesNot(t *testing.T) {
	h, _ := alertingServer(t)
	rec, out := call(t, h, http.MethodPost, "/v1/tenants", `{"name":"eds"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %v", rec.Code, out)
	}
	if pw, _ := dig(out, "notify", "password").(string); len(pw) != 48 {
		t.Fatalf("notify password = %q", pw)
	}
	for k, want := range map[string]string{"endpoint": "https://ntfy.mobile.deevnet.net", "username": "eds", "topic_prefix": "eds-"} {
		if got := dig(out, "notify", k); got != want {
			t.Errorf("notify.%s = %v, want %s", k, got, want)
		}
	}
	_, out = call(t, h, http.MethodGet, "/v1/tenants/eds", "")
	if dig(out, "notify", "password") != nil {
		t.Error("a GET returned the ntfy password")
	}
	if dig(out, "notify", "username") != "eds" {
		t.Error("a GET dropped the ntfy username")
	}
}

func TestARuleGroupIsPutReadListedAndDeleted(t *testing.T) {
	h, b := alertingServer(t)
	token := createTenantFor(t, h, "eds")

	rec, body := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/alert-rule-groups/backend", backendGroupJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if body["ntfy_topic"] != "eds-backend" || body["interval"] != "1m" || body["partition"] != "workloads" {
		t.Errorf("body = %v", body)
	}
	if len(b.Alerts["eds"].Groups) != 1 {
		t.Error("the group did not reach the writer")
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/alert-rule-groups/backend", ""); rec.Code != http.StatusOK {
		t.Errorf("get: %d", rec.Code)
	}
	rec, body = callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/alert-rule-groups", "")
	if groups, _ := body["alert_rule_groups"].([]any); rec.Code != http.StatusOK || len(groups) != 1 {
		t.Errorf("list: %d %v", rec.Code, body)
	}
	if rec, _ := callAs(t, h, token, http.MethodDelete, "/v1/tenants/eds/alert-rule-groups/backend", ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d", rec.Code)
	}
	if rec, _ := callAs(t, h, token, http.MethodGet, "/v1/tenants/eds/alert-rule-groups/backend", ""); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete: %d", rec.Code)
	}
}

// The spoof Step 2 proved works against vmalert itself: refused here.
func TestARuleLabelledAsAnotherTenantIs400(t *testing.T) {
	h, b := alertingServer(t)
	createTenantFor(t, h, "eds")
	token := createTenantFor(t, h, "tdemo")
	spoof := strings.Replace(backendGroupJSON, `"for":"5m"`, `"for":"5m","labels":{"tenant":"eds"}`, 1)
	rec, body := callAs(t, h, token, http.MethodPut, "/v1/tenants/tdemo/alert-rule-groups/backend", spoof)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, `"tenant"`) {
		t.Errorf("error = %q", msg)
	}
	if len(b.Alerts["tdemo"].Groups) != 0 || len(b.Alerts["eds"].Groups) != 0 {
		t.Error("the spoofed group reached the writer")
	}
}

func TestVMAlertsRefusalIs400WithItsReason(t *testing.T) {
	h, b := alertingServer(t)
	token := createTenantFor(t, h, "eds")
	b.AlertsInvalid = `the rules do not load: bad MetricsQL expr: "sum(("`
	rec, body := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/alert-rule-groups/backend", backendGroupJSON)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %v", rec.Code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "bad MetricsQL expr") {
		t.Errorf("error = %q", msg)
	}
}

func TestAnotherTenantsRuleGroupsAre404(t *testing.T) {
	h, _ := alertingServer(t)
	eds := createTenantFor(t, h, "eds")
	other := createTenantFor(t, h, "tdemo")
	callAs(t, h, eds, http.MethodPut, "/v1/tenants/eds/alert-rule-groups/backend", backendGroupJSON)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/tenants/eds/alert-rule-groups", ""},
		{http.MethodGet, "/v1/tenants/eds/alert-rule-groups/backend", ""},
		{http.MethodPut, "/v1/tenants/eds/alert-rule-groups/sneaky", backendGroupJSON},
		{http.MethodDelete, "/v1/tenants/eds/alert-rule-groups/backend", ""},
	} {
		if rec, _ := callAs(t, h, other, c.method, c.path, c.body); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s as another tenant = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}

func TestAnUnknownFieldInAGroupIs400(t *testing.T) {
	h, _ := alertingServer(t)
	token := createTenantFor(t, h, "eds")
	rec, _ := callAs(t, h, token, http.MethodPut, "/v1/tenants/eds/alert-rule-groups/backend",
		strings.Replace(backendGroupJSON, `"type":"metrics"`, `"type":"metrics","record":"x:sum"`, 1))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("%d", rec.Code)
	}
}
