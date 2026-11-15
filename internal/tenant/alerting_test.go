package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/logauth"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func alertingService(t *testing.T) (*tenant.Service, *tenanttest.Store, *tenanttest.Backends) {
	t.Helper()
	svc, st, b := tenanttest.NewService()
	svc.Site.NotifyEndpoint = "https://ntfy.site.example"
	svc.Alerting = b.Alerting()
	return svc, st, b
}

func backendGroup() logauth.AlertGroup {
	return logauth.AlertGroup{
		Name: "backend", Type: logauth.AlertTypeMetrics, Topic: "backend",
		Rules: []logauth.AlertRule{{Alert: "QueueBacklog", Expr: "backend_queue_depth > 100", For: "5m"}},
	}
}

func TestATenantGetsAnNtfyLoginOnCreate(t *testing.T) {
	svc, _, b := alertingService(t)
	res, err := svc.Create(context.Background(), tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Issued.NotifyPassword) != 48 {
		t.Fatalf("notify password = %q", res.Issued.NotifyPassword)
	}
	got, ok := b.Alerts["eds"]
	if !ok || got.NotifyPassword != res.Issued.NotifyPassword || len(got.Groups) != 0 {
		t.Fatalf("the writer has %+v", got)
	}
	// A reconcile hands the same login back, and does not mint another.
	rec, err := svc.Reconcile(context.Background(), "eds")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Issued.NotifyPassword != res.Issued.NotifyPassword {
		t.Error("reconcile changed the ntfy login")
	}
}

func TestASiteWithoutAlertingIssuesNoLogin(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	res, err := svc.Create(context.Background(), tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Issued.NotifyPassword != "" || len(b.Alerts) != 0 {
		t.Error("a site with no alerting issued an ntfy login")
	}
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup()); !errors.Is(err, tenant.ErrAlertingNotOffered) {
		t.Errorf("err = %v, want ErrAlertingNotOffered", err)
	}
}

func TestARuleGroupIsWrittenThenRecorded(t *testing.T) {
	svc, st, b := alertingService(t)
	ready(t, svc, "eds")
	g, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup())
	if err != nil {
		t.Fatal(err)
	}
	if g.Group.Interval != "1m" || g.Group.Partition != "workloads" {
		t.Errorf("defaults not applied: %+v", g.Group)
	}
	if n := len(b.Alerts["eds"].Groups); n != 1 {
		t.Fatalf("the writer has %d groups", n)
	}
	// Replacing it keeps one group.
	g2 := backendGroup()
	g2.Rules[0].Expr = "backend_queue_depth > 200"
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", g2); err != nil {
		t.Fatal(err)
	}
	if gs := b.Alerts["eds"].Groups; len(gs) != 1 || gs[0].Rules[0].Expr != "backend_queue_depth > 200" {
		t.Fatalf("the writer has %+v", gs)
	}
	stored, err := st.ListAlertRuleGroups(context.Background(), "eds")
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored = %v, %v", stored, err)
	}
}

// The labels Alertmanager routes on are refused before anything is sent.
func TestARuleThatLabelsItselfAnotherTenantIsRefused(t *testing.T) {
	svc, st, b := alertingService(t)
	ready(t, svc, "tdemo")
	ready(t, svc, "eds")
	g := backendGroup()
	g.Rules[0].Labels = map[string]string{"tenant": "eds"}
	_, err := svc.PutAlertRuleGroup(context.Background(), "tdemo", g)
	var bad *tenant.InvalidError
	if !errors.As(err, &bad) || !strings.Contains(bad.Reason, "tenant") {
		t.Fatalf("err = %v, want an invalid label", err)
	}
	if len(b.Alerts["tdemo"].Groups) != 0 {
		t.Error("the refused group reached the writer")
	}
	if gs, _ := st.ListAlertRuleGroups(context.Background(), "tdemo"); len(gs) != 0 {
		t.Error("the refused group was recorded")
	}
}

// vmalert's refusal of the tenant's own rules comes back as a 400 and the
// group is not recorded.
func TestRulesTheWriterRefusesAreNotRecorded(t *testing.T) {
	svc, st, b := alertingService(t)
	ready(t, svc, "eds")
	b.AlertsInvalid = `the rules do not load: invalid expression for rule "QueueBacklog"`
	_, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup())
	var bad *tenant.InvalidError
	if !errors.As(err, &bad) || !strings.Contains(bad.Reason, "QueueBacklog") {
		t.Fatalf("err = %v", err)
	}
	if gs, _ := st.ListAlertRuleGroups(context.Background(), "eds"); len(gs) != 0 {
		t.Error("a group vmalert refused was recorded")
	}
}

func TestAnUnreachableWriterIsAStepError(t *testing.T) {
	svc, st, b := alertingService(t)
	ready(t, svc, "eds")
	b.AlertsErr = errors.New("connection refused")
	_, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup())
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepAlerting {
		t.Fatalf("err = %v, want a step error", err)
	}
	if gs, _ := st.ListAlertRuleGroups(context.Background(), "eds"); len(gs) != 0 {
		t.Error("a group the writer never took was recorded")
	}
}

func TestDeletingAGroupTakesItOffTheWriterFirst(t *testing.T) {
	svc, st, b := alertingService(t)
	ready(t, svc, "eds")
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup()); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteAlertRuleGroup(context.Background(), "eds", "backend"); err != nil {
		t.Fatal(err)
	}
	if n := len(b.Alerts["eds"].Groups); n != 0 {
		t.Errorf("the writer still has %d groups", n)
	}
	if _, err := st.GetAlertRuleGroup(context.Background(), "eds", "backend"); !errors.Is(err, tenant.ErrNotFound) {
		t.Error("the group is still recorded")
	}
	if err := svc.DeleteAlertRuleGroup(context.Background(), "eds", "backend"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("deleting it again: %v", err)
	}
}

func TestReconcileRewritesEveryGroup(t *testing.T) {
	svc, _, b := alertingService(t)
	ready(t, svc, "eds")
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup()); err != nil {
		t.Fatal(err)
	}
	// A rebuilt observability store has nothing.
	delete(b.Alerts, "eds")
	if _, err := svc.Reconcile(context.Background(), "eds"); err != nil {
		t.Fatal(err)
	}
	if n := len(b.Alerts["eds"].Groups); n != 1 {
		t.Errorf("after a reconcile the writer has %d groups", n)
	}
}

func TestRemovingATenantRemovesItsAlerting(t *testing.T) {
	svc, _, b := alertingService(t)
	ready(t, svc, "eds")
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", backendGroup()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(context.Background(), "eds"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Alerts["eds"]; ok {
		t.Error("the removed tenant's alerting is still on the writer")
	}
}

func TestTenantLimitsAcrossGroups(t *testing.T) {
	svc, _, _ := alertingService(t)
	ready(t, svc, "eds")
	for i := 0; i < logauth.MaxAlertGroups; i++ {
		g := backendGroup()
		g.Name = "g" + string(rune('a'+i))
		if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", g); err != nil {
			t.Fatalf("group %d: %v", i, err)
		}
	}
	g := backendGroup()
	g.Name = "one-too-many"
	var bad *tenant.InvalidError
	if _, err := svc.PutAlertRuleGroup(context.Background(), "eds", g); !errors.As(err, &bad) {
		t.Fatalf("err = %v, want the group limit", err)
	}
}
