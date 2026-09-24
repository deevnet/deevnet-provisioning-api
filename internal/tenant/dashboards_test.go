package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// A tenant is created with a dashboard login, and its data sources carry the
// read token it was issued - the one the store was told about.
func TestCreateGivesTheTenantItsDashboards(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(res.Issued.DashboardPassword) != 48 {
		t.Fatalf("dashboard password = %q, want 48 hex characters", res.Issued.DashboardPassword)
	}
	got, ok := b.DashTenants["eds"]
	if !ok {
		t.Fatal("the dashboard server was never told about the tenant")
	}
	if got.ReadToken != res.Issued.LogReadToken || got.ReadToken == "" {
		t.Error("the data sources carry a token that is not the tenant's read token")
	}
	if got.Password != res.Issued.DashboardPassword || got.Index != res.Record.Index {
		t.Error("the server was told a login the tenant was not given")
	}
	rec, _ := st.Get(ctx, "eds")
	if rec.DashboardOrg != b.DashOrgs["eds"] || rec.DashboardOrg < 2 {
		t.Errorf("registry org = %d, server gave %d", rec.DashboardOrg, b.DashOrgs["eds"])
	}
}

// A tenant that predates the dashboard server gets its login on reconcile, and
// a second reconcile hands back the same password rather than a new one.
func TestReconcileMintsADashboardLoginOnceAndReturnsIt(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rec, _ := st.Get(ctx, "eds")
	secrets := rec.Secrets
	secrets.DashboardPassword = ""
	_ = st.SetSecrets(ctx, "eds", secrets)
	delete(b.DashTenants, "eds")

	first, err := svc.Reconcile(ctx, "eds")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if first.Issued.DashboardPassword == "" || b.DashTenants["eds"].Password != first.Issued.DashboardPassword {
		t.Fatal("reconcile did not mint and write a login")
	}
	second, err := svc.Reconcile(ctx, "eds")
	if err != nil || second.Issued.DashboardPassword != first.Issued.DashboardPassword {
		t.Fatalf("a second reconcile changed the password (%v)", err)
	}
}

// Delete takes the dashboards out, and a server that refuses stops the delete
// with the tenant still registered, so it can be finished by calling again.
func TestDeleteRemovesDashboardsFirst(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	b.DashErr = errors.New("server down")
	var step *tenant.StepError
	if err := svc.Delete(ctx, "eds"); !errors.As(err, &step) || step.Step != tenant.StepDashboard {
		t.Fatalf("delete = %v, want the dashboards step to fail", err)
	}
	if _, ok := b.LogTenants["eds"]; !ok {
		t.Error("the log tokens were removed before the dashboards that hold them")
	}
	b.DashErr = nil
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatalf("delete again: %v", err)
	}
	if _, ok := b.DashTenants["eds"]; ok {
		t.Error("the dashboard server still has the tenant")
	}
	if _, err := st.Get(ctx, "eds"); !errors.Is(err, tenant.ErrNotFound) {
		t.Error("the tenant is still registered")
	}
}

// A site with no dashboard server still creates tenants, with no login.
func TestNoDashboardServerMeansNoLogin(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.Dashboards = nil
	res, err := svc.Create(context.Background(), tenant.CreateRequest{Name: "eds"})
	if err != nil || res.Issued.DashboardPassword != "" || res.Record.DashboardOrg != 0 {
		t.Fatalf("create = %v, password %q, org %d", err, res.Issued.DashboardPassword, res.Record.DashboardOrg)
	}
}
