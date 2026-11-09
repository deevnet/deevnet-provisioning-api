package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// A reissue mints a new state secret, records it and sets it on the store, and
// leaves every other secret as it was (CHG-0060).
func TestReissueStateSecretReplacesOnlyTheStateSecret(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	created, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before, _ := st.Get(ctx, "eds")

	res, err := svc.ReissueStateSecret(ctx, "eds")
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	got := res.Issued.StateSecret
	if len(got) != 40 {
		t.Fatalf("issued state secret %q, want 40 hex characters", got)
	}
	if got == created.Issued.StateSecret {
		t.Fatal("the reissue handed back the old secret")
	}
	if b.States["eds"].Secret != got {
		t.Error("the store was not given the new secret")
	}
	after, _ := st.Get(ctx, "eds")
	if after.Secrets.State != got {
		t.Error("the registry does not hold the new secret, so a reconcile would put the old one back")
	}
	want := before.Secrets
	want.State = got
	if after.Secrets.TSIG != want.TSIG || string(after.Secrets.APITokenHash) != string(want.APITokenHash) ||
		after.Secrets.LogIngest != want.LogIngest || after.Secrets.LogRead != want.LogRead ||
		after.Secrets.DashboardPassword != want.DashboardPassword {
		t.Error("the reissue changed a secret other than the state secret")
	}
	if res.Issued.TSIGSecret != "" || res.Issued.APIToken != "" || res.Issued.LogReadToken != "" {
		t.Error("the reissue returned more than the state secret")
	}
	last := st.AuditLog[len(st.AuditLog)-1]
	if last.Action != "reissue-state-secret" || last.Tenant != "eds" {
		t.Errorf("last audit entry = %+v, want the reissue", last)
	}
}

// A store that refuses the new secret returns none. The registry already holds
// it, so a reconcile puts the store right, and asking again mints another.
func TestReissueStateSecretReturnsNothingWhenTheStoreFails(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	b.FailState = errors.New("store down")

	res, err := svc.ReissueStateSecret(ctx, "eds")
	var step *tenant.StepError
	if !errors.As(err, &step) || step.Step != tenant.StepState {
		t.Fatalf("err = %v, want a failed state step", err)
	}
	if res.Issued.StateSecret != "" {
		t.Error("a secret the store may not hold was returned")
	}

	b.FailState = nil
	if _, err := svc.Reconcile(ctx, "eds"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rec, _ := st.Get(ctx, "eds")
	if b.States["eds"].Secret != rec.Secrets.State {
		t.Error("the reconcile did not bring the store into line with the registry")
	}
}

// With secrets the API cannot read, writing the row back would store them
// empty, so the reissue refuses until the tenant has supplied them again.
func TestReissueStateSecretRefusesUnreadableSecrets(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rec, _ := st.Get(ctx, "eds")
	secrets := rec.Secrets
	secrets.Unreadable = true
	if err := st.SetSecrets(ctx, "eds", secrets); err != nil {
		t.Fatalf("marking unreadable: %v", err)
	}

	_, err := svc.ReissueStateSecret(ctx, "eds")
	var inv *tenant.InvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("err = %v, want invalid", err)
	}
	after, _ := st.Get(ctx, "eds")
	if after.Secrets.State != rec.Secrets.State {
		t.Error("a refused reissue changed the stored secret")
	}
}

func TestReissueStateSecretOfAnUnknownTenant(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	if _, err := svc.ReissueStateSecret(context.Background(), "nope"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
}
