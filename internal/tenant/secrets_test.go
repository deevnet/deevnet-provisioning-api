package tenant_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// readyTenantWithWorkload makes eds with one workload, web.
func readyTenantWithWorkload(t *testing.T) (*tenant.Service, *tenanttest.Store, *tenanttest.Backends, tenant.Workload) {
	t.Helper()
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	w, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "web"})
	if err != nil {
		t.Fatalf("workload: %v", err)
	}
	return svc, st, b, w
}

func TestCreateMakesTheTenantsNamespace(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	res, err := svc.Create(context.Background(), tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatal(err)
	}
	mounts, ok := b.Bao.Namespaces["tenants/eds"]
	if !ok || mounts["secrets"] != "kv-v2" || mounts["approle"] != "approle" || len(mounts) != 2 {
		t.Fatalf("namespace = %v, %v", mounts, ok)
	}
	var stepped bool
	for _, s := range res.Record.Steps {
		stepped = stepped || (s.Name == tenant.StepSecrets && s.OK)
	}
	if !stepped {
		t.Error("no secrets step recorded")
	}
}

// Ensure is idempotent: a reconcile after the namespace was lost brings it
// back, and one with it there changes nothing.
func TestReconcileRemakesALostNamespace(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reconcile(ctx, "eds"); err != nil {
		t.Fatalf("reconcile with the namespace there: %v", err)
	}
	delete(b.Bao.Namespaces, "tenants/eds")
	if _, err := svc.Reconcile(ctx, "eds"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if b.Bao.Namespaces["tenants/eds"]["secrets"] != "kv-v2" {
		t.Error("the namespace was not made again")
	}
}

// Delete removes the namespace before anything else of the tenant's, and a
// failure stops the delete with the tenant still registered.
func TestDeleteRemovesTheNamespaceFirst(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	ctx := context.Background()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"}); err != nil {
		t.Fatal(err)
	}
	b.Bao.Err = errors.New("openbao down")
	var step *tenant.StepError
	if err := svc.Delete(ctx, "eds"); !errors.As(err, &step) || step.Step != tenant.StepSecrets {
		t.Fatalf("delete = %v, want the secrets step to fail", err)
	}
	if _, ok := b.DashTenants["eds"]; !ok {
		t.Error("the dashboards went before the namespace")
	}
	b.Bao.Err = nil
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Fatalf("delete again: %v", err)
	}
	if _, ok := b.Bao.Namespaces["tenants/eds"]; ok {
		t.Error("the namespace is still there")
	}
	if _, err := st.Get(ctx, "eds"); !errors.Is(err, tenant.ErrNotFound) {
		t.Error("the tenant is still registered")
	}
}

func TestNoSecretsServiceMeansNoStepAndNotOffered(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	svc.TenantSecrets = nil
	ctx := context.Background()
	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Record.Steps {
		if s.Name == tenant.StepSecrets {
			t.Error("a secrets step was recorded at a site without the service")
		}
	}
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); !errors.Is(err, tenant.ErrSecretsNotOffered) {
		t.Errorf("put: %v", err)
	}
	if err := svc.Delete(ctx, "eds"); err != nil {
		t.Errorf("delete: %v", err)
	}
}

func TestSecretWriteKeepsNoValue(t *testing.T) {
	svc, st, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	sec, err := svc.PutRuntimeSecret(ctx, "eds", "weather/api", map[string]string{"key": "s3cr3t-value"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sec.Path != "weather/api" || sec.Version != 1 {
		t.Errorf("put = %+v", sec)
	}
	if b.Bao.KV["tenants/eds/weather/api"]["key"] != "s3cr3t-value" {
		t.Error("the value did not reach the tenant's namespace")
	}
	got, err := svc.GetRuntimeSecret(ctx, "eds", "weather/api")
	if err != nil || got.Version != 1 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	for _, e := range st.AuditLog {
		for _, v := range e.Detail {
			if s, ok := v.(string); ok && strings.Contains(s, "s3cr3t") {
				t.Errorf("the audit log holds the value: %+v", e)
			}
		}
	}

	// A new version writes again.
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "weather/api", map[string]string{"key": "rotated"}, 2); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetRuntimeSecret(ctx, "eds", "weather/api"); got.Version != 2 {
		t.Errorf("version = %d", got.Version)
	}
}

// After an OpenBao rebuild the registry still has the row, and a read says
// the secret is gone so the provider writes it again.
func TestASecretOpenBaoLostReadsAsNotFound(t *testing.T) {
	svc, _, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	delete(b.Bao.Versions, "tenants/eds/a")
	if _, err := svc.GetRuntimeSecret(ctx, "eds", "a"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("get = %v, want ErrNotFound", err)
	}
	b.Bao.Err = tenant.ErrSecretsUnavailable
	if _, err := svc.GetRuntimeSecret(ctx, "eds", "a"); !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Errorf("sealed: %v, want ErrSecretsUnavailable", err)
	}
}

func TestSecretPathsAreRefused(t *testing.T) {
	svc, _, _, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	for _, p := range []string{"", "A", "a/", "/a", "a//b", "a/b/c/d/e", "../x", "a.b", "a b",
		strings.Repeat("a", 65), strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789/", 4)} {
		var inv *tenant.InvalidError
		if _, err := svc.PutRuntimeSecret(ctx, "eds", p, map[string]string{"k": "v"}, 1); !errors.As(err, &inv) {
			t.Errorf("path %q: %v, want refused", p, err)
		}
	}
	for _, p := range []string{"a", "a_b-c/d", "a/b/c/d", strings.Repeat("a", 64)} {
		if !tenant.ValidSecretPath(p) {
			t.Errorf("path %q refused", p)
		}
	}
	var inv *tenant.InvalidError
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 0); !errors.As(err, &inv) {
		t.Errorf("version 0: %v", err)
	}
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", nil, 1); !errors.As(err, &inv) {
		t.Errorf("no data: %v", err)
	}
}

func TestDeleteSecret(t *testing.T) {
	svc, _, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	// Already gone from OpenBao is fine.
	delete(b.Bao.Versions, "tenants/eds/a")
	if err := svc.DeleteRuntimeSecret(ctx, "eds", "a"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteRuntimeSecret(ctx, "eds", "a"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestReaderIsBoundToItsWorkloadAndPaths(t *testing.T) {
	svc, st, b, w := readyTenantWithWorkload(t)
	ctx := context.Background()
	for _, p := range []string{"a", "b/c"} {
		if _, err := svc.PutRuntimeSecret(ctx, "eds", p, map[string]string{"k": "v"}, 1); err != nil {
			t.Fatal(err)
		}
	}
	r, err := svc.PutSecretReader(ctx, "eds", "backend", "web", []string{"a", "b/c", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if r.RoleID == "" || r.SecretID == "" || r.Namespace != "tenants/eds" || r.Addr != "https://bao.site.example:8200" {
		t.Errorf("reader = %+v", r)
	}
	if len(r.Paths) != 2 {
		t.Errorf("paths = %v, want duplicates dropped", r.Paths)
	}
	role := b.Bao.Roles["tenants/eds/backend"]
	if len(role.BoundCIDRs) != 1 || role.BoundCIDRs[0] != w.Address+"/32" {
		t.Errorf("bound to %v, want %s/32", role.BoundCIDRs, w.Address)
	}
	if len(role.TokenPolicies) != 1 || role.TokenPolicies[0] != "reader-backend" ||
		role.TokenTTL != "1h" || role.TokenMaxTTL != "24h" || role.SecretIDTTL != "0" || role.SecretIDNumUses != 0 {
		t.Errorf("role = %+v", role)
	}
	pol := b.Bao.Policies["tenants/eds/reader-backend"]
	want := "path \"secrets/data/a\" {\n  capabilities = [\"read\"]\n}\npath \"secrets/data/b/c\" {\n  capabilities = [\"read\"]\n}\n"
	if pol != want {
		t.Errorf("policy =\n%s\nwant\n%s", pol, want)
	}
	if got, err := st.GetSecretReader(ctx, "eds", "backend"); err != nil || got.Workload != "web" {
		t.Errorf("registry = %+v, %v", got, err)
	}

	// A read gives the role ID and never a secret ID.
	got, err := svc.GetSecretReader(ctx, "eds", "backend")
	if err != nil || got.SecretID != "" || got.RoleID != r.RoleID {
		t.Errorf("get = %+v, %v", got, err)
	}
}

func TestReaderRefusesWhatIsNotTheTenants(t *testing.T) {
	svc, _, _, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		reader, workload string
		paths            []string
	}{
		"undeclared path":  {"backend", "web", []string{"a", "nope"}},
		"unknown workload": {"backend", "db", []string{"a"}},
		"no paths":         {"backend", "web", nil},
		"bad path":         {"backend", "web", []string{"../a"}},
		"bad name":         {"Backend", "web", []string{"a"}},
		"long name":        {strings.Repeat("r", 33), "web", []string{"a"}},
	} {
		var inv *tenant.InvalidError
		if _, err := svc.PutSecretReader(ctx, "eds", tc.reader, tc.workload, tc.paths); !errors.As(err, &inv) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "a"
	}
	var inv *tenant.InvalidError
	if _, err := svc.PutSecretReader(ctx, "eds", "backend", "web", many); !errors.As(err, &inv) {
		t.Errorf("33 paths: %v", err)
	}
}

// Putting a reader again replaces its AppRole, so a secret ID issued before
// stops logging in.
func TestReaderPutReplacesTheOldAppRole(t *testing.T) {
	svc, _, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	first, err := svc.PutSecretReader(ctx, "eds", "backend", "web", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	b.Bao.Calls = nil
	second, err := svc.PutSecretReader(ctx, "eds", "backend", "web", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Bao.Calls) == 0 || b.Bao.Calls[0] != "delete-approle tenants/eds backend" {
		t.Errorf("calls = %v, want the old AppRole deleted first", b.Bao.Calls)
	}
	ids := b.Bao.SecretIDs["tenants/eds/backend"]
	if len(ids) != 1 || ids[0] != second.SecretID || second.SecretID == first.SecretID {
		t.Errorf("secret IDs held = %v; the first (%s) must be gone", ids, first.SecretID)
	}
}

// A reader delete removes the AppRole AND its policy: a held token outlives
// its AppRole, but not its policy (ADR-0021 §5).
func TestReaderDeleteRemovesRoleAndPolicy(t *testing.T) {
	svc, st, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutSecretReader(ctx, "eds", "backend", "web", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteSecretReader(ctx, "eds", "backend"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Bao.Roles["tenants/eds/backend"]; ok {
		t.Error("the AppRole is still there")
	}
	if _, ok := b.Bao.Policies["tenants/eds/reader-backend"]; ok {
		t.Error("the policy is still there; a held token would keep reading")
	}
	if _, err := st.GetSecretReader(ctx, "eds", "backend"); !errors.Is(err, tenant.ErrNotFound) {
		t.Error("the registry still has the reader")
	}
}

// A reader whose AppRole OpenBao lost reads as not found, so it is issued again.
func TestReaderOpenBaoLostReadsAsNotFound(t *testing.T) {
	svc, _, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutSecretReader(ctx, "eds", "backend", "web", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	delete(b.Bao.RoleIDs, "tenants/eds/backend")
	if _, err := svc.GetSecretReader(ctx, "eds", "backend"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("get = %v, want ErrNotFound", err)
	}
}

// Destroying a workload revokes its readers and only its readers.
func TestWorkloadDeleteRemovesItsReaders(t *testing.T) {
	svc, st, b, _ := readyTenantWithWorkload(t)
	ctx := context.Background()
	if _, err := svc.CreateWorkload(ctx, "eds", tenant.WorkloadRequest{Name: "api"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutRuntimeSecret(ctx, "eds", "a", map[string]string{"k": "v"}, 1); err != nil {
		t.Fatal(err)
	}
	for reader, wl := range map[string]string{"web-a": "web", "web-b": "web", "api-a": "api"} {
		if _, err := svc.PutSecretReader(ctx, "eds", reader, wl, []string{"a"}); err != nil {
			t.Fatal(err)
		}
	}
	// A failing OpenBao stops the delete before the VM goes.
	b.Bao.Err = errors.New("down")
	if err := svc.DeleteWorkload(ctx, "eds", "web"); err == nil {
		t.Fatal("the workload was deleted with its readers unrevoked")
	}
	if _, err := st.GetWorkload(ctx, "eds", "web"); err != nil {
		t.Errorf("the workload went: %v", err)
	}
	b.Bao.Err = nil
	if err := svc.DeleteWorkload(ctx, "eds", "web"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"web-a", "web-b"} {
		if _, ok := b.Bao.Roles["tenants/eds/"+r]; ok {
			t.Errorf("%s's AppRole is still there", r)
		}
		if _, ok := b.Bao.Policies["tenants/eds/reader-"+r]; ok {
			t.Errorf("%s's policy is still there", r)
		}
		if _, err := st.GetSecretReader(ctx, "eds", r); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("%s is still registered", r)
		}
	}
	if _, ok := b.Bao.Roles["tenants/eds/api-a"]; !ok {
		t.Error("another workload's reader was revoked")
	}
}
