package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// A tenant is created with a pair of log tokens, and the store is told what
// they are. The index crosses too, because the partitions are derived from it
// at both ends rather than being sent (ADR-0027 §2).
func TestCreateIssuesLogTokensAndTellsTheStore(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(res.Issued.LogIngestToken) != 64 || len(res.Issued.LogReadToken) != 64 {
		t.Fatalf("issued log tokens = %q and %q, want 64 hex characters each",
			res.Issued.LogIngestToken, res.Issued.LogReadToken)
	}
	if res.Issued.LogIngestToken == res.Issued.LogReadToken {
		t.Error("one token was issued for both roles; the read user would be a writer")
	}
	got, ok := b.LogTenants["eds"]
	if !ok {
		t.Fatal("the log store was never told about the tenant")
	}
	if got.Index != res.Record.Index {
		t.Errorf("the store was told index %d, the tenant has %d", got.Index, res.Record.Index)
	}
	if got.IngestToken != res.Issued.LogIngestToken || got.ReadToken != res.Issued.LogReadToken {
		t.Error("the store was told tokens the tenant was not given")
	}
	// And the registry keeps them, because they are re-asserted on reconcile.
	rec, _ := st.Get(ctx, "eds")
	if rec.Secrets.LogIngest != res.Issued.LogIngestToken || rec.Secrets.LogRead != res.Issued.LogReadToken {
		t.Error("the registry does not hold the tenant's log tokens")
	}
}

// A tenant that predates the store has empty columns. Reconcile mints a pair
// and writes it, which is how tdemo and eds are handed theirs without being
// rebuilt.
func TestReconcileMintsLogTokensForATenantThatHasNone(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Forget them, as a tenant created before CHG-0020 has.
	rec, _ := st.Get(ctx, "eds")
	secrets := rec.Secrets
	secrets.LogIngest, secrets.LogRead = "", ""
	if err := st.SetSecrets(ctx, "eds", secrets); err != nil {
		t.Fatalf("clearing: %v", err)
	}
	delete(b.LogTenants, "eds")

	res, err := svc.Reconcile(ctx, "eds")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(res.Issued.LogIngestToken) != 64 || len(res.Issued.LogReadToken) != 64 {
		t.Fatal("reconcile did not hand back a pair of log tokens")
	}
	if _, ok := b.LogTenants["eds"]; !ok {
		t.Fatal("reconcile did not tell the store")
	}
	rec, _ = st.Get(ctx, "eds")
	if rec.Secrets.LogIngest != res.Issued.LogIngestToken {
		t.Error("the registry kept a different token from the one returned")
	}
}

// A store that cannot be reached fails the step, and the tenant is left
// provisioning rather than ready with a credential nothing honours.
func TestAStoreThatRefusesFailsTheStep(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	b.LogErr = errors.New("connection refused")

	_, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepLogStore {
		t.Fatalf("create error = %v, want a log-store step error", err)
	}
	rec, err := st.Get(ctx, "eds")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if rec.Status != tenant.StatusProvisioning {
		t.Errorf("tenant status = %q, want provisioning", rec.Status)
	}
}

// Deleting a tenant takes its users out of the store. A row removed while the
// store still honoured the token would leave a working credential belonging to
// nobody.
func TestDeleteRemovesTheTenantFromTheStore(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := b.LogTenants["eds"]; ok {
		t.Error("the store still holds the tenant's users")
	}
}
