package tenant_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// A sealed OpenBao is unavailable, never a lost secret (ADR-0042 §3). Reconcile
// is the call that re-mints an empty log token or dashboard password, so it is
// the one that would replace working secrets if a sealed store read as empty.
func TestASealedStoreRefusesAndChangesNothing(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before, _ := st.Get(ctx, "eds")
	told := b.LogTenants["eds"]

	st.Sealed = true
	if _, err := svc.Reconcile(ctx, "eds"); !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Fatalf("reconcile while sealed: %v, want ErrSecretsUnavailable", err)
	}
	if _, ok, err := svc.Authenticate(ctx, res.Issued.APIToken); ok || !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Fatalf("authenticate while sealed: ok=%v err=%v, want unavailable, not refused", ok, err)
	}

	st.Sealed = false
	after, _ := st.Get(ctx, "eds")
	if !reflect.DeepEqual(after.Secrets, before.Secrets) {
		t.Error("a sealed store changed the tenant's stored secrets")
	}
	if b.LogTenants["eds"] != told {
		t.Error("a sealed store changed what the log store was told")
	}
	if c, ok, err := svc.Authenticate(ctx, res.Issued.APIToken); err != nil || !ok || !c.Registered {
		t.Fatalf("authenticate after unsealing: %+v %v %v", c, ok, err)
	}
}
