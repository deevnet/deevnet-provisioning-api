package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

// These tests need a PostgreSQL they may wipe. They are skipped unless
// DEEVNET_TEST_DATABASE_URL names one; `make test-integration` starts one.
func testStore(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("DEEVNET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("DEEVNET_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS audit_log, admission_keys, tenant_steps, tenant_workloads, tenant_wifi_keys, tenant_device_addresses, tenant_devices, tenant_broker_accounts, tenant_certificates, tenant_records, tenants, schema_migrations CASCADE`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	p := New(pool)
	if err := p.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A second run is a no-op.
	if err := p.Migrate(ctx); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	return p
}

func lowest(held map[int]string) (int, error) {
	for n := tenant.MinIndex; n <= tenant.MaxAllocatable; n++ {
		if _, ok := held[n]; !ok {
			return n, nil
		}
	}
	return 0, tenant.ErrExhausted
}

// A Transit key that no longer exists is what a rebuilt OpenBao leaves behind
// (ADR-0016 §6). The tenant must still read back, so its own state can supply
// the secrets again; failing the read would make it unable to authenticate and
// close the only way back.
type refusingSealer struct{}

func (refusingSealer) Seal(_ context.Context, plaintext string) (string, error) {
	return "vault:v1:" + plaintext, nil
}

func (refusingSealer) Open(_ context.Context, _ string) (string, error) {
	return "", errors.New("decrypt: key not found")
}

// The flag says "held and unreadable", not "empty". A store with no sealer holds
// its columns in the clear, so nothing is unreadable however they read.
func TestSecretsAreNotUnreadableWithoutASealer(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	if _, err := p.Create(ctx, "tplain", tenant.Secrets{TSIG: "", State: "",
		APITokenHash: tenant.HashToken("t")}, lowest); err != nil {
		t.Fatal(err)
	}
	got, err := p.Get(ctx, "tplain")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secrets.Unreadable {
		t.Error("empty columns are not unreadable ones")
	}
}

func TestASecretThatWillNotOpenLosesTheSecretNotTheTenant(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	secrets := tenant.Secrets{TSIG: "tsig-secret", State: "state-secret", APITokenHash: tenant.HashToken("t")}
	rec, err := p.Create(ctx, "tprobe", secrets, lowest)
	if err != nil {
		t.Fatal(err)
	}

	// From here the key that wrote those columns is gone.
	p.WithSealer(refusingSealer{})
	got, err := p.Get(ctx, "tprobe")
	if err != nil {
		t.Fatalf("the tenant must still read back: %v", err)
	}
	if got.Index != rec.Index || got.Name != "tprobe" {
		t.Errorf("record came back wrong: %+v", got)
	}
	if got.Secrets.TSIG != "" || got.Secrets.State != "" {
		t.Errorf("an unreadable secret must read as empty, got %q / %q", got.Secrets.TSIG, got.Secrets.State)
	}
	if !got.Secrets.Unreadable {
		t.Error("the record must say its secrets are unreadable, or the tenant is never told to supply them again")
	}
	if !bytes.Equal(got.Secrets.APITokenHash, tenant.HashToken("t")) {
		t.Error("the token hash is not sealed and must survive, or the tenant cannot authenticate")
	}
}

func TestStoreLifecycle(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()

	secrets := tenant.Secrets{TSIG: "dHNpZw==", State: "state-secret", APITokenHash: tenant.HashToken("tok")}
	rec, err := p.Create(ctx, "tdemo", secrets, lowest)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec.Index != 1 || rec.Status != tenant.StatusProvisioning {
		t.Fatalf("created %+v, want index 1 provisioning", rec)
	}
	if _, err := p.Create(ctx, "tdemo", secrets, lowest); !errors.Is(err, tenant.ErrExists) {
		t.Fatalf("duplicate create: %v, want ErrExists", err)
	}

	if err := p.RecordStep(ctx, "tdemo", tenant.StepDNS, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordStep(ctx, "tdemo", tenant.StepResolver, errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	if err := p.RecordStep(ctx, "tdemo", tenant.StepResolver, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.SetStatus(ctx, "tdemo", tenant.StatusReady); err != nil {
		t.Fatal(err)
	}
	newSecrets := tenant.Secrets{TSIG: "bmV3", State: "new-state-secret", APITokenHash: tenant.HashToken("new")}
	if err := p.SetSecrets(ctx, "tdemo", newSecrets); err != nil {
		t.Fatal(err)
	}

	got, err := p.Get(ctx, "tdemo")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != tenant.StatusReady || got.Secrets.State != "new-state-secret" || string(got.Secrets.APITokenHash) != string(tenant.HashToken("new")) {
		t.Fatalf("got %+v", got)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("steps = %+v, want dns and resolver", got.Steps)
	}
	for _, s := range got.Steps {
		if !s.OK || s.Error != "" {
			t.Errorf("step %+v, want ok with no error after the retry", s)
		}
	}

	if err := p.Audit(ctx, tenant.AuditEntry{Actor: "operator", Action: "create", Tenant: "tdemo", Detail: map[string]any{"index": 1}}); err != nil {
		t.Fatal(err)
	}

	if err := p.Delete(ctx, "tdemo"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := p.SetStatus(ctx, "tdemo", tenant.StatusReady); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("update after delete: %v", err)
	}
	var audits int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant = 'tdemo'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit rows = %d (%v), want 1 surviving the tenant", audits, err)
	}
}

func TestConcurrentCreatesNeverShareAnIndex(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.Create(ctx, fmt.Sprintf("t%d", i), tenant.Secrets{TSIG: "x", State: "y", APITokenHash: []byte{1}}, lowest)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	recs, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]string{}
	for _, r := range recs {
		if other, dup := seen[r.Index]; dup {
			t.Fatalf("index %d given to %s and %s", r.Index, other, r.Name)
		}
		seen[r.Index] = r.Name
	}
	if len(seen) != n {
		t.Fatalf("%d tenants, want %d", len(seen), n)
	}
}

// The service against the real registry: the rules hold with PostgreSQL behind
// them, not only with the in-memory fake.
func TestServiceOverPostgres(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	svc, _, b := tenanttest.NewService()
	svc.Store = p

	first, err := svc.Create(ctx, tenant.CreateRequest{Name: "eds"})
	if err != nil {
		t.Fatal(err)
	}
	b.FabricClaims = []tenant.Claim{{Index: 2, Zone: "orphan"}}
	second, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Record.Index != 1 || second.Record.Index != 3 || second.Record.Status != tenant.StatusReady {
		t.Fatalf("indexes %d and %d (%s), want 1 and 3 ready", first.Record.Index, second.Record.Index, second.Record.Status)
	}
	// dns, resolver, state, network, device-address, log-store and dashboards.
	if len(second.Record.Steps) != 7 {
		t.Fatalf("steps = %+v", second.Record.Steps)
	}
}

// fakeSealer marks values instead of encrypting them, so the test can see
// what reached the database.
type fakeSealer struct{}

func (fakeSealer) Seal(_ context.Context, v string) (string, error) { return "vault:v1:" + v, nil }
func (fakeSealer) Open(_ context.Context, v string) (string, error) {
	return strings.TrimPrefix(v, "vault:v1:"), nil
}

func TestSecretsAreSealedAtRest(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()

	// A row written before encryption was turned on.
	if _, err := p.Create(ctx, "legacy", tenant.Secrets{TSIG: "old-tsig", State: "old-state", APITokenHash: []byte{1}}, lowest); err != nil {
		t.Fatal(err)
	}
	p.WithSealer(fakeSealer{})

	rec, err := p.Create(ctx, "tdemo", tenant.Secrets{TSIG: "tsig", State: "state", APITokenHash: []byte{2}}, lowest)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Secrets.TSIG != "tsig" {
		t.Errorf("create returned %q, want the plaintext", rec.Secrets.TSIG)
	}
	var tsig, state string
	if err := p.pool.QueryRow(ctx, `SELECT tsig_secret, state_secret FROM tenants WHERE name = 'tdemo'`).Scan(&tsig, &state); err != nil {
		t.Fatal(err)
	}
	if tsig != "vault:v1:tsig" || state != "vault:v1:state" {
		t.Fatalf("stored %q %q, want sealed values", tsig, state)
	}
	got, err := p.Get(ctx, "tdemo")
	if err != nil || got.Secrets.TSIG != "tsig" || got.Secrets.State != "state" {
		t.Fatalf("get = %+v %v", got.Secrets, err)
	}
	legacy, err := p.Get(ctx, "legacy")
	if err != nil || legacy.Secrets.TSIG != "old-tsig" {
		t.Fatalf("a row stored before encryption reads as it is: %+v %v", legacy.Secrets, err)
	}
	if err := p.SetSecrets(ctx, "legacy", legacy.Secrets); err != nil {
		t.Fatal(err)
	}
	if err := p.pool.QueryRow(ctx, `SELECT tsig_secret FROM tenants WHERE name = 'legacy'`).Scan(&tsig); err != nil || tsig != "vault:v1:old-tsig" {
		t.Fatalf("rewritten legacy row = %q %v, want sealed", tsig, err)
	}
	recs, _ := p.List(ctx)
	for _, r := range recs {
		if r.Secrets.TSIG != "" || r.Secrets.State != "" {
			t.Errorf("list carried secrets for %s", r.Name)
		}
	}
}

// The dashboard password is sealed like the log tokens, and the organisation
// the server chose is kept beside it (CHG-0024).
func TestDashboardLoginIsSealedAndItsOrgKept(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	p.WithSealer(fakeSealer{})

	if _, err := p.Create(ctx, "eds", tenant.Secrets{TSIG: "t", State: "s", APITokenHash: []byte{1}, DashboardPassword: "pw"}, lowest); err != nil {
		t.Fatal(err)
	}
	if err := p.SetDashboardOrg(ctx, "eds", 7); err != nil {
		t.Fatal(err)
	}
	var stored string
	var org int
	if err := p.pool.QueryRow(ctx, `SELECT dashboard_password, dashboard_org FROM tenants WHERE name = 'eds'`).Scan(&stored, &org); err != nil {
		t.Fatal(err)
	}
	if stored != "vault:v1:pw" || org != 7 {
		t.Fatalf("stored %q / %d, want a sealed password and org 7", stored, org)
	}
	got, err := p.Get(ctx, "eds")
	if err != nil || got.Secrets.DashboardPassword != "pw" || got.DashboardOrg != 7 {
		t.Fatalf("get = %q / %d (%v)", got.Secrets.DashboardPassword, got.DashboardOrg, err)
	}
	// An unreadable one reads as empty, to be re-minted - and is not reported
	// as a secret the tenant must supply.
	p.WithSealer(refusingSealer{})
	got, err = p.Get(ctx, "eds")
	if err != nil || got.Secrets.DashboardPassword != "" {
		t.Fatalf("unreadable password read as %q (%v)", got.Secrets.DashboardPassword, err)
	}
}

// A sealed OpenBao is not a rebuilt Transit key: nothing is lost, so nothing
// may read as empty, or the next ensure re-mints log tokens, passwords and
// Wi-Fi keys that still work (ADR-0042 §3).
type sealedSealer struct{}

func (sealedSealer) Seal(context.Context, string) (string, error) {
	return "", fmt.Errorf("openbao: encrypt: %w", tenant.ErrSecretsUnavailable)
}

func (sealedSealer) Open(context.Context, string) (string, error) {
	return "", fmt.Errorf("openbao: decrypt: %w", tenant.ErrSecretsUnavailable)
}

// prefixSealer is a Transit stand-in that opens what it sealed.
type prefixSealer struct{}

func (prefixSealer) Seal(_ context.Context, plaintext string) (string, error) {
	return "vault:v1:" + plaintext, nil
}

func (prefixSealer) Open(_ context.Context, stored string) (string, error) {
	return strings.TrimPrefix(stored, "vault:v1:"), nil
}

func TestASealedStoreFailsTheReadAndForgetsNothing(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	p.WithSealer(prefixSealer{})
	secrets := tenant.Secrets{TSIG: "tsig-secret", State: "state-secret", LogIngest: "ingest",
		LogRead: "read", DashboardPassword: "dash", APITokenHash: tenant.HashToken("t")}
	if _, err := p.Create(ctx, "tsealed", secrets, lowest); err != nil {
		t.Fatal(err)
	}
	if err := p.PutAdmissionKey(ctx, tenant.AdmissionKey{Tenant: "tsealed", PSK: "admission-psk", MAC: "02:00:00:00:00:01"}); err != nil {
		t.Fatal(err)
	}

	p.WithSealer(sealedSealer{})
	if _, err := p.Get(ctx, "tsealed"); !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Fatalf("get while sealed: %v, want ErrSecretsUnavailable", err)
	}
	if _, err := p.GetAdmissionKey(ctx, "tsealed"); !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Fatalf("admission key while sealed: %v, want ErrSecretsUnavailable", err)
	}
	if _, err := p.ListWiFiKeys(ctx, "tsealed"); err != nil {
		t.Fatalf("an empty key list needs nothing opened: %v", err)
	}
	if _, err := p.Create(ctx, "tsealed2", secrets, lowest); !errors.Is(err, tenant.ErrSecretsUnavailable) {
		t.Fatalf("create while sealed: %v, want ErrSecretsUnavailable", err)
	}
	if _, err := p.Get(ctx, "tsealed2"); !errors.Is(err, tenant.ErrNotFound) {
		t.Fatalf("a create refused while sealed left a row: %v", err)
	}

	p.WithSealer(prefixSealer{})
	got, err := p.Get(ctx, "tsealed")
	if err != nil {
		t.Fatal(err)
	}
	got.Secrets.Unreadable = false
	if got.Secrets.TSIG != secrets.TSIG || got.Secrets.State != secrets.State || got.Secrets.LogIngest != secrets.LogIngest ||
		got.Secrets.LogRead != secrets.LogRead || got.Secrets.DashboardPassword != secrets.DashboardPassword {
		t.Errorf("secrets changed across a seal: %+v", got.Secrets)
	}
	k, err := p.GetAdmissionKey(ctx, "tsealed")
	if err != nil || k.PSK != "admission-psk" || k.Unreadable {
		t.Errorf("admission key after unsealing: %+v %v", k, err)
	}
}

// keyedSealer stands in for Transit with a current and a previous key; a
// ciphertext names its key so the wrong one refuses it.
type keyedSealer struct{ current, previous string }

func (k keyedSealer) Seal(_ context.Context, plaintext string) (string, error) {
	return "vault:v1:" + k.current + ":" + plaintext, nil
}

func (k keyedSealer) Open(_ context.Context, stored string) (string, error) {
	for _, key := range []string{k.current, k.previous} {
		if key == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(stored, "vault:v1:"+key+":"); ok {
			return rest, nil
		}
	}
	return "", errors.New("decrypt: refused")
}

func (k keyedSealer) Reseal(ctx context.Context, stored string) (string, bool, error) {
	if strings.HasPrefix(stored, "vault:v1:"+k.current+":") {
		return stored, false, nil
	}
	plain, err := k.Open(ctx, stored)
	if err != nil {
		return "", false, err
	}
	s, _ := k.Seal(ctx, plain)
	return s, true, nil
}

func TestResealMovesEverySealedColumn(t *testing.T) {
	p := testStore(t)
	ctx := context.Background()
	p.WithSealer(keyedSealer{current: "old"})
	secrets := tenant.Secrets{TSIG: "tsig", State: "state", LogIngest: "ingest", LogRead: "read",
		DashboardPassword: "dash", APITokenHash: tenant.HashToken("t")}
	if _, err := p.Create(ctx, "treseal", secrets, lowest); err != nil {
		t.Fatal(err)
	}
	if err := p.PutAdmissionKey(ctx, tenant.AdmissionKey{Tenant: "treseal", PSK: "admission", MAC: "02:00:00:00:00:02"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PutWiFiKey(ctx, tenant.WiFiKey{Tenant: "treseal", Name: "k1", PSK: "wifi", TrustClass: "iot", Status: tenant.StatusReady}); err != nil {
		t.Fatal(err)
	}
	// One value already under the new key, and one under a key that is gone.
	if _, err := p.pool.Exec(ctx, `UPDATE tenants SET log_read_token = 'vault:v1:new:read', dashboard_password = 'vault:v1:gone:dash' WHERE name = 'treseal'`); err != nil {
		t.Fatal(err)
	}

	ks := keyedSealer{current: "new", previous: "old"}
	p.WithSealer(ks)
	rep, err := p.Reseal(ctx, ks)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(rep.Resealed); n != 5 || rep.Current != 1 || rep.Failed["tenants.dashboard_password"] != 1 {
		t.Fatalf("report %+v, want 5 columns resealed, 1 current, the gone one failed", rep)
	}

	var raw []string
	for _, q := range []string{
		`SELECT tsig_secret FROM tenants WHERE name = 'treseal'`,
		`SELECT state_secret FROM tenants WHERE name = 'treseal'`,
		`SELECT log_ingest_token FROM tenants WHERE name = 'treseal'`,
		`SELECT log_read_token FROM tenants WHERE name = 'treseal'`,
		`SELECT psk FROM admission_keys WHERE tenant = 'treseal'`,
		`SELECT psk FROM tenant_wifi_keys WHERE tenant = 'treseal'`,
	} {
		var v string
		if err := p.pool.QueryRow(ctx, q).Scan(&v); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, v)
	}
	for _, v := range raw {
		if !strings.HasPrefix(v, "vault:v1:new:") {
			t.Errorf("%q is not under the new key", v)
		}
	}
	var gone string
	p.pool.QueryRow(ctx, `SELECT dashboard_password FROM tenants WHERE name = 'treseal'`).Scan(&gone)
	if gone != "vault:v1:gone:dash" {
		t.Errorf("a value neither key opens was changed: %q", gone)
	}

	// Only the new key from here: everything that moved still opens.
	p.WithSealer(keyedSealer{current: "new"})
	got, err := p.Get(ctx, "treseal")
	if err != nil {
		t.Fatal(err)
	}
	if got.Secrets.TSIG != "tsig" || got.Secrets.State != "state" || got.Secrets.LogIngest != "ingest" || got.Secrets.LogRead != "read" {
		t.Errorf("secrets after the reseal: %+v", got.Secrets)
	}

	// A second run moves nothing.
	if rep, err := p.Reseal(ctx, ks); err != nil || len(rep.Resealed) != 0 {
		t.Errorf("second run: %+v %v, want nothing resealed", rep, err)
	}
}
