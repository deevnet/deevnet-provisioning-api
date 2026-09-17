package tenant_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

var ctx = context.Background()

func TestCreateAllocatesLowestFreeIndexAndEnsuresEveryBackend(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	st.Put(tenant.Record{Name: "eds", Index: 1, Status: tenant.StatusReady})

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 2 || res.Outcome != tenant.OutcomeCreated || res.Record.Status != tenant.StatusReady {
		t.Fatalf("got index %d outcome %s status %s, want 2 created ready", res.Record.Index, res.Outcome, res.Record.Status)
	}

	dns, ok := b.DNSTenants["tdemo"]
	if !ok {
		t.Fatal("DNS was not ensured")
	}
	wantZones := []string{"tdemo.mobile.deevnet.net", "130.20.10.in-addr.arpa"}
	if strings.Join(dns.Zones, ",") != strings.Join(wantZones, ",") || dns.Secret != res.Issued.TSIGSecret || dns.Algorithm != "hmac-sha256" {
		t.Errorf("DNS tenant = %+v, want zones %v and the issued secret", dns, wantZones)
	}
	for _, z := range wantZones {
		if f, ok := b.Forwards[z]; !ok || f.Server != "10.20.25.21" {
			t.Errorf("forward for %s = %+v, want to 10.20.25.21", z, f)
		}
	}
	if s := b.States["tdemo"]; s.Prefix != "tenants/tdemo/" || s.Bucket != "tf-state" || s.Secret != res.Issued.StateSecret {
		t.Errorf("state tenant = %+v", s)
	}

	if raw, err := base64.StdEncoding.DecodeString(res.Issued.TSIGSecret); err != nil || len(raw) != 32 {
		t.Errorf("TSIG secret is not base64 of 32 bytes")
	}
	if len(res.Issued.StateSecret) != 40 || len(res.Issued.APIToken) != 64 {
		t.Errorf("state secret %d chars, token %d chars; want 40 and 64", len(res.Issued.StateSecret), len(res.Issued.APIToken))
	}
	rec, _ := st.Get(ctx, "tdemo")
	if string(rec.Secrets.APITokenHash) != string(tenant.HashToken(res.Issued.APIToken)) {
		t.Error("the registry does not hold the token's hash")
	}
	if len(rec.Steps) != 3 {
		t.Errorf("steps recorded = %v, want dns, resolver and state", rec.Steps)
	}
}

func TestAllocationSkipsIndexesTheFabricCarries(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	// Zones left on the fabric after the registry was lost.
	b.FabricClaims = []tenant.Claim{{Index: 1, Zone: "eds"}, {Index: 2, Zone: "other"}}

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 3 {
		t.Fatalf("index = %d, want 3", res.Record.Index)
	}
}

func TestCreateWithoutStateReusesTheIndexItsOwnZoneHolds(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	b.FabricClaims = []tenant.Claim{{Index: 5, Zone: "tdemo"}}

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Record.Index != 5 {
		t.Fatalf("index = %d, want 5, the index the fabric already uses for this tenant", res.Record.Index)
	}
}

func restore(name string, index int) tenant.CreateRequest {
	return tenant.CreateRequest{
		Name:        name,
		Index:       index,
		TSIGSecret:  base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		StateSecret: "state-secret-from-tenant-state",
		APIToken:    strings.Repeat("t", 64),
	}
}

func TestRestoreKeepsAFreeIndexAndTheSuppliedSecrets(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	req := restore("tdemo", 7)
	// Its own zone is still on the fabric: the same tenant coming back.
	b.FabricClaims = []tenant.Claim{{Index: 7, Zone: "tdemo"}}

	res, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != 7 || res.Outcome != tenant.OutcomeRestored {
		t.Fatalf("got index %d outcome %s, want 7 restored", res.Record.Index, res.Outcome)
	}
	if b.DNSTenants["tdemo"].Secret != req.TSIGSecret || b.States["tdemo"].Secret != req.StateSecret {
		t.Error("the backends were not given the restored secrets")
	}
	rec, _ := st.Get(ctx, "tdemo")
	if string(rec.Secrets.APITokenHash) != string(tenant.HashToken(req.APIToken)) {
		t.Error("the registry does not hold the restored token's hash")
	}
}

func TestRestoreIsIssuedANewIndexWhenAnotherTenantTookIt(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	st.Put(tenant.Record{Name: "grooveiq", Index: 7, Status: tenant.StatusReady})

	res, err := svc.Create(ctx, restore("tdemo", 7))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != 1 || res.Outcome != tenant.OutcomeReissued {
		t.Fatalf("got index %d outcome %s, want 1 reissued", res.Record.Index, res.Outcome)
	}
}

func TestRestoreIsReissuedWhenTheFabricHoldsAnotherTenantsZone(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	b.FabricClaims = []tenant.Claim{{Index: 7, Zone: "grooveiq"}}

	res, err := svc.Create(ctx, restore("tdemo", 7))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index == 7 || res.Outcome != tenant.OutcomeReissued {
		t.Fatalf("got index %d outcome %s, want a new index, reissued", res.Record.Index, res.Outcome)
	}
}

func TestSecondCreateOfAReadyTenantIsRefused(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); !errors.Is(err, tenant.ErrExists) {
		t.Fatalf("err = %v, want ErrExists", err)
	}
}

func TestRestoreOverASurvivingRegistryKeepsTheRegistryIndex(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	first, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatal(err)
	}

	req := restore("tdemo", 9)
	res, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Record.Index != first.Record.Index || res.Outcome != tenant.OutcomeReconciled {
		t.Fatalf("got index %d outcome %s, want %d reconciled", res.Record.Index, res.Outcome, first.Record.Index)
	}
	if b.DNSTenants["tdemo"].Secret != req.TSIGSecret {
		t.Error("supplied secrets must win: the tenant's state is the authoritative copy")
	}
	rec, _ := st.Get(ctx, "tdemo")
	if rec.Secrets.State != req.StateSecret {
		t.Error("the registry kept the old state secret")
	}
}

func TestFailedStepLeavesTheTenantResumable(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	b.FailResolver = errors.New("dial tcp 10.20.25.1:443: connection refused")

	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	var stepErr *tenant.StepError
	if !errors.As(err, &stepErr) || stepErr.Step != tenant.StepResolver {
		t.Fatalf("err = %v, want a resolver StepError", err)
	}
	if strings.Contains(err.Error(), "10.20.25.1") {
		t.Errorf("the error message leaks the backend error: %q", err)
	}
	if res.Record.Status != tenant.StatusProvisioning {
		t.Fatalf("status = %s, want provisioning", res.Record.Status)
	}
	if _, ok := b.States["tdemo"]; ok {
		t.Error("the state step ran after the resolver step failed")
	}
	firstIndex := res.Record.Index

	b.FailResolver = nil
	res, err = svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.Outcome != tenant.OutcomeResumed || res.Record.Status != tenant.StatusReady || res.Record.Index != firstIndex {
		t.Fatalf("got %s %s index %d, want resumed ready index %d", res.Outcome, res.Record.Status, res.Record.Index, firstIndex)
	}
	// The first response never reached the caller, so its token is replaced.
	rec, _ := st.Get(ctx, "tdemo")
	if res.Issued.APIToken == "" || string(rec.Secrets.APITokenHash) != string(tenant.HashToken(res.Issued.APIToken)) {
		t.Error("a resume must issue a new token and store its hash")
	}
}

func TestDeleteIsRefusedWhileTheFabricCarriesTheZone(t *testing.T) {
	svc, _, b := tenanttest.NewService()
	res, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"})
	if err != nil {
		t.Fatal(err)
	}
	b.FabricClaims = []tenant.Claim{{Index: res.Record.Index, Zone: "tdemo"}}

	if err := svc.Delete(ctx, "tdemo"); !errors.Is(err, tenant.ErrFabricInUse) {
		t.Fatalf("err = %v, want ErrFabricInUse", err)
	}
	if len(b.DNSTenants) != 1 {
		t.Fatal("DNS was removed although the delete was refused")
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	svc, st, b := tenanttest.NewService()
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "tdemo"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "tdemo"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(b.DNSTenants)+len(b.Forwards)+len(b.States) != 0 {
		t.Errorf("left behind: dns %v forwards %v state %v", b.DNSTenants, b.Forwards, b.States)
	}
	if _, err := st.Get(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("registry row survived: %v", err)
	}
	if err := svc.Delete(ctx, "tdemo"); !errors.Is(err, tenant.ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
}

func TestIndexExhaustion(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	for n := tenant.MinIndex; n <= tenant.MaxAllocatable; n++ {
		st.Put(tenant.Record{Name: fmt.Sprintf("t%d", n), Index: n})
	}
	if _, err := svc.Create(ctx, tenant.CreateRequest{Name: "late"}); !errors.Is(err, tenant.ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted; index 63 is reserved and never allocated", err)
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _, _ := tenanttest.NewService()
	half := restore("tdemo", 3)
	half.APIToken = ""
	for name, req := range map[string]tenant.CreateRequest{
		"name too long":      {Name: "toolongname"},
		"name upper":         {Name: "TDemo"},
		"reserved index":     {Name: "tdemo", Index: 63},
		"half a restore":     half,
		"short state secret": func() tenant.CreateRequest { r := restore("tdemo", 3); r.StateSecret = "short"; return r }(),
	} {
		var inv *tenant.InvalidError
		if _, err := svc.Create(ctx, req); !errors.As(err, &inv) {
			t.Errorf("%s: err = %v, want InvalidError", name, err)
		}
	}
}

func TestEgressListsReadyTenantsOnly(t *testing.T) {
	svc, st, _ := tenanttest.NewService()
	st.Put(tenant.Record{Name: "eds", Index: 1, Status: tenant.StatusReady})
	st.Put(tenant.Record{Name: "half", Index: 2, Status: tenant.StatusProvisioning})

	got, err := svc.Egress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VRF != "vrf_eds" {
		t.Fatalf("egress = %v, want only vrf_eds", got)
	}
}

func TestNumbering(t *testing.T) {
	site := tenanttest.MobileSite()
	n := site.Numbering(1)
	want := tenant.Numbering{Index: 1, VRFVNI: 10001, VNetVNIBase: 20010, Subnet: "10.20.129.0/24", Gateway: "10.20.129.1", ReverseZone: "129.20.10.in-addr.arpa"}
	if n != want {
		t.Fatalf("numbering(1) = %+v, want %+v", n, want)
	}
	if site.IndexForVRFVNI(10001) != 1 || site.IndexForVRFVNI(9999) != 0 || site.IndexForVRFVNI(10064) != 0 {
		t.Error("IndexForVRFVNI")
	}
	if site.IndexForVNetTag(20010) != 1 || site.IndexForVNetTag(20019) != 1 || site.IndexForVNetTag(20020) != 2 || site.IndexForVNetTag(20005) != 0 {
		t.Error("IndexForVNetTag")
	}
}
